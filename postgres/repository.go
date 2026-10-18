// Package postgres supplies organization persistence through identity's one
// coordinator. Repositories never own a coordinator, transaction or registry.
package postgres

import (
	"context"
	"errors"
	"math"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Config borrows an already migrated PRIMARY pool with a positive read budget
// no greater than five seconds. There are no defaults, caches or background jobs.
type Config struct{ MaximumDuration time.Duration }

// Repository supplies current uncached membership reads and delegates exact
// target user reads to the existing identity owner. Pool shutdown stays caller-
// owned. Immutable configuration permits concurrent independent operations.
type Repository struct {
	pool      *database.Pool
	directory *kernel.Repository
	maximum   time.Duration
}

var _ organization.Repository = (*Repository)(nil)

func NewRepository(pool *database.Pool, c Config) (*Repository, error) {
	if pool == nil || pool.Raw() == nil || c.MaximumDuration <= 0 || c.MaximumDuration > 5*time.Second {
		return nil, organization.ErrInvalidInput
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration})
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	return &Repository{pool: pool, directory: directory, maximum: c.MaximumDuration}, nil
}

// Read rechecks the actor's active membership and organization on every call.
// It is a trusted storage projection, not an authentication endpoint: public
// callers use Service, which supplies genuine session and policy admission.
// Pagination is exclusive bytewise UserID keyset over current committed state,
// not a retained snapshot; additions before the cursor require a new listing.
func (r *Repository) Read(ctx context.Context, q organization.Query) (organization.View, error) {
	if ctx == nil || r == nil || r.pool == nil || !scope(string(q.TenantID)) || !scope(string(q.ActorID)) || !scope(string(q.OrganizationID)) {
		return organization.View{}, organization.ErrInvalidInput
	}
	if q.Operation != organization.Get && q.Operation != organization.ListMembers && q.Operation != organization.AddMember && q.Operation != organization.RemoveMember {
		return organization.View{}, organization.ErrInvalidInput
	}
	if q.Operation == organization.ListMembers && (q.Limit < 1 || q.Limit > 100 || q.Cursor != "" && !scope(string(q.Cursor))) {
		return organization.View{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	v := organization.View{}
	var version, owners, member, authority string
	err := r.pool.Raw().QueryRow(bounded, `SELECT o.slug,o.name,o.version::text,o.owner_count::text,a.role,a.version::text,a.authorization_version::text
FROM organization.organizations o JOIN organization.memberships a USING(tenant_id,organization_id)
WHERE o.tenant_id=$1 AND o.organization_id=$2 AND a.user_id=$3 AND o.state='active' AND a.state='active'`, string(q.TenantID), string(q.OrganizationID), string(q.ActorID)).Scan(&v.Organization.Slug, &v.Organization.Name, &version, &owners, &v.Actor.Role, &member, &authority)
	if err != nil {
		return organization.View{}, storageError(bounded, err)
	}
	v.Organization.ID, v.Organization.TenantID, v.Organization.Active = q.OrganizationID, q.TenantID, true
	v.Actor.OrganizationID, v.Actor.TenantID, v.Actor.UserID, v.Actor.Active = q.OrganizationID, q.TenantID, q.ActorID, true
	var e error
	if v.Organization.Version, e = positive(version); e != nil {
		return organization.View{}, e
	}
	if v.OwnerCount, e = positive(owners); e != nil {
		return organization.View{}, e
	}
	if v.Actor.Version, e = positive(member); e != nil {
		return organization.View{}, e
	}
	if v.Actor.AuthorizationVersion, e = positive(authority); e != nil {
		return organization.View{}, e
	}
	if q.Operation == organization.AddMember || q.Operation == organization.RemoveMember {
		if !scope(string(q.TargetID)) {
			return organization.View{}, organization.ErrInvalidInput
		}
		v.Target = organization.Member{OrganizationID: q.OrganizationID, TenantID: q.TenantID, UserID: q.TargetID}
		err = r.pool.Raw().QueryRow(bounded, `SELECT role,version::text,authorization_version::text,state='active' FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(q.TenantID), string(q.OrganizationID), string(q.TargetID)).Scan(&v.Target.Role, &member, &authority, &v.Target.Active)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return organization.View{}, storageError(bounded, err)
		}
		if err == nil {
			if v.Target.Version, e = positive(member); e != nil {
				return organization.View{}, e
			}
			if v.Target.AuthorizationVersion, e = positive(authority); e != nil {
				return organization.View{}, e
			}
		}
		v.TargetUser, err = r.directory.Get(bounded, identity.GetUserQuery{TenantID: q.TenantID, UserID: q.TargetID})
		if err != nil {
			return organization.View{}, storageError(bounded, err)
		}
	}
	if q.Operation == organization.ListMembers {
		rows, err := r.pool.Raw().Query(bounded, `SELECT user_id,role,version::text,authorization_version::text FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND state='active' AND user_id>$3 COLLATE "C" ORDER BY user_id COLLATE "C" LIMIT $4`, string(q.TenantID), string(q.OrganizationID), string(q.Cursor), int32(q.Limit+1))
		if err != nil {
			return organization.View{}, storageError(bounded, err)
		}
		defer rows.Close()
		for rows.Next() {
			m := organization.Member{OrganizationID: q.OrganizationID, TenantID: q.TenantID, Active: true}
			if err = rows.Scan(&m.UserID, &m.Role, &member, &authority); err != nil {
				return organization.View{}, storageError(bounded, err)
			}
			if m.Version, e = positive(member); e != nil {
				return organization.View{}, e
			}
			if m.AuthorizationVersion, e = positive(authority); e != nil {
				return organization.View{}, e
			}
			if len(v.Members) == int(q.Limit) {
				v.NextCursor = v.Members[len(v.Members)-1].UserID
				break
			}
			v.Members = append(v.Members, m)
		}
		if err = rows.Err(); err != nil {
			return organization.View{}, storageError(bounded, err)
		}
	}
	if bounded.Err() != nil {
		return organization.View{}, bounded.Err()
	}
	return v, nil
}

// MigrationSource installs only this owner's forward-only schema. Version must
// be permanently allocated after the identity and authorization owner migrations
// in the composition's one migration history. Existing unmanaged objects fail.
type MigrationSource struct{ Version migrations.Version }

func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_memberships", migrations.TransactionModeDefault, schemaSQL, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const schemaSQL = `CREATE SCHEMA organization;
CREATE TABLE organization.tenant_locks(tenant_id identity.directory_id PRIMARY KEY);
CREATE TABLE organization.organizations(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 slug text COLLATE "C" NOT NULL CHECK(slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
 name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 256),
 state text NOT NULL CHECK(state IN('active','archived','deleted')),
 version identity.version NOT NULL,
 member_count bigint NOT NULL CHECK(member_count>=1),
 owner_count bigint NOT NULL CHECK(owner_count>=1 AND owner_count<=member_count),
 PRIMARY KEY(tenant_id,organization_id),UNIQUE(tenant_id,slug)
);
CREATE TABLE organization.memberships(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 role text NOT NULL CHECK(role IN('owner','administrator','member')),
 state text NOT NULL CHECK(state IN('active','removed')),
 version identity.version NOT NULL,
 authorization_version identity.version NOT NULL,
 PRIMARY KEY(tenant_id,organization_id,user_id),
 FOREIGN KEY(tenant_id,organization_id) REFERENCES organization.organizations(tenant_id,organization_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
CREATE INDEX organization_member_user ON organization.memberships(tenant_id,user_id,organization_id) WHERE state='active';
CREATE INDEX organization_member_page ON organization.memberships(tenant_id,organization_id,user_id) WHERE state='active';
CREATE TABLE organization.command_effects(
 command_id text COLLATE "C" PRIMARY KEY CHECK(command_id ~ '^[A-Za-z0-9_-]{22}$'),
 tenant_id identity.directory_id NOT NULL,organization_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,actor_id identity.directory_id NOT NULL,
 operation text NOT NULL,fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 before_version numeric NOT NULL CHECK(before_version>=0 AND scale(before_version)=0),
 after_version identity.version NOT NULL CHECK(after_version=before_version+1)
);`

func positive(raw string) (uint64, error) {
	n, e := strconv.ParseUint(raw, 10, 64)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != raw {
		return 0, organization.ErrUnavailable
	}
	return n, nil
}
func scope(s string) bool {
	return (identity.User{ID: identity.UserID(s), TenantID: "scope", Status: identity.StatusActive, Version: 1}).Validate("scope") == nil
}
func storageError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, identity.ErrUserAbsent) {
		return organization.ErrForbidden
	}
	var p *pgconn.PgError
	if errors.As(err, &p) && (p.Code == "23505" || p.Code == "40001" || p.Code == "40P01") {
		return organization.ErrConflict
	}
	return organization.ErrUnavailable
}
