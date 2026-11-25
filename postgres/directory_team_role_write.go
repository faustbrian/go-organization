package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

const directoryTeamRoleField = "organization.directory-team-role"

// DirectoryTeamRoleUpdate binds one existing native team-role selection to the
// exact original Group contribution. It is input, not source authority or a
// receipt; zero is invalid. The Group command must include both update Fields.
type DirectoryTeamRoleUpdate struct{ state *directoryTeamRoleUpdateState }

type directoryTeamRoleUpdateState struct {
	grant          DirectoryTeamGrantUpdate
	source         DirectoryTeamRoleSource
	bindingVersion uint64
	digest         [32]byte
}

// NewDirectoryTeamRoleUpdate freezes the exact source, current primary source
// versions and selected native binding version without IO. It cannot create a
// role or team-role binding. Withdrawals retain the original selection even if
// that native binding has subsequently changed or been removed.
func NewDirectoryTeamRoleUpdate(grant DirectoryTeamGrantUpdate, source DirectoryTeamRoleSource, bindingVersion uint64) (DirectoryTeamRoleUpdate, error) {
	if grant.state == nil || source.Scope != grant.state.input.Scope || !scope(string(source.MemberResourceID)) ||
		!scope(string(source.RoleID)) || source.ProviderVersion == 0 || source.MappingVersion == 0 ||
		source.ConnectionVersion == 0 || grant.state.input.Active && bindingVersion == 0 {
		return DirectoryTeamRoleUpdate{}, organization.ErrInvalidInput
	}
	wire, err := json.Marshal(struct {
		Grant          DirectoryTeamGrantInput
		Source         DirectoryTeamRoleSource
		BindingVersion uint64
	}{grant.state.input, source, bindingVersion})
	if err != nil {
		return DirectoryTeamRoleUpdate{}, organization.ErrInvalidInput
	}
	digest := sha256.Sum256(append([]byte("organization.directory-team-role-update.v1\x00"), wire...))
	return DirectoryTeamRoleUpdate{&directoryTeamRoleUpdateState{grant: grant, source: source, bindingVersion: bindingVersion, digest: digest}}, nil
}

// Field returns detached digest bytes for the original Group command. It
// discloses no source identifiers and supplies no application authority.
func (u DirectoryTeamRoleUpdate) Field() (identity.FeatureField, error) {
	if u.state == nil {
		return identity.FeatureField{}, organization.ErrInvalidInput
	}
	return identity.FeatureField{Name: directoryTeamRoleField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(u.state.digest[:])}}, nil
}

func (DirectoryTeamRoleUpdate) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryTeamRoleUpdate(redacted)"))
}

// DirectoryTeamRoleLock belongs only to the unchanged original Work, command,
// owner and update. It retains lock order and its own provisional successor,
// never authority that can be restored or carried into another transaction.
type DirectoryTeamRoleLock struct{ state *directoryTeamRoleLockState }

type directoryTeamRoleLockState struct {
	work                kernel.Work
	command             identity.Command
	owner               kernel.FeatureExecutionContributor
	update              *directoryTeamRoleUpdateState
	member              organization.Member
	organizationVersion uint64
	roleVersion         uint64
	applied             bool
}

func (DirectoryTeamRoleLock) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryTeamRoleLock(redacted)"))
}

func requireDirectoryTeamRoleBinding(w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryTeamRoleUpdate) error {
	if update.state == nil {
		return identity.ForbiddenError{}
	}
	if err := requireDirectoryTeamGrantBinding(w, owner, command, update.state.grant); err != nil {
		return err
	}
	spec, _ := command.Feature()
	matches := 0
	for _, field := range spec.Fields {
		if field.Name == directoryTeamRoleField {
			if field.Value.Kind != identity.FeatureBytes || !bytes.Equal(field.Value.Bytes, update.state.digest[:]) {
				return identity.ForbiddenError{}
			}
			matches++
		}
	}
	if matches != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

// LockDirectoryTeamRoleUpdate locks the target identity, tenant and native
// organization writer before the source owner takes an organization SHARE or
// connection lock. Invoke only in the original Group Apply. The caller must
// subsequently fence its exact provider, mapping, connection and Group source;
// this organization seam does not authenticate any of them.
func (r *Repository) LockDirectoryTeamRoleUpdate(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryTeamRoleUpdate) (DirectoryTeamRoleLock, error) {
	if r == nil || r.pool == nil || ctx == nil {
		return DirectoryTeamRoleLock{}, identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return DirectoryTeamRoleLock{}, err
	}
	if err := requireDirectoryTeamRoleBinding(w, owner, command, update); err != nil {
		return DirectoryTeamRoleLock{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	i := update.state.grant.state.input
	if err := w.RequireActiveTargetUser(ctx, owner, i.User); err != nil {
		return DirectoryTeamRoleLock{}, err
	}
	if err := lockMembershipTenant(ctx, w, i.Scope.TenantID); err != nil {
		return DirectoryTeamRoleLock{}, err
	}
	if err := requireDirectoryTeamRoleOrganization(ctx, w, i, i.OrganizationVersion); err != nil {
		return DirectoryTeamRoleLock{}, err
	}
	if err := r.requireDirectoryTeamGrantTarget(ctx, w, owner, i); err != nil {
		return DirectoryTeamRoleLock{}, err
	}
	member, err := readMember(ctx, w, i.Scope.TenantID, i.Scope.OrganizationID, i.Scope.UserID)
	if err != nil {
		return DirectoryTeamRoleLock{}, err
	}
	locked := &directoryTeamRoleLockState{work: w, command: command, owner: owner, update: update.state, member: member, organizationVersion: i.OrganizationVersion}
	if i.Active {
		locked.roleVersion, err = requireDirectoryTeamRoleSelection(ctx, w, update.state)
		if err != nil {
			return DirectoryTeamRoleLock{}, err
		}
	}
	return DirectoryTeamRoleLock{locked}, nil
}

func requireDirectoryTeamRoleLock(w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryTeamRoleUpdate, locked DirectoryTeamRoleLock) error {
	if err := requireDirectoryTeamRoleBinding(w, owner, command, update); err != nil {
		return err
	}
	// FeatureScope above establishes that owner is a comparable live participant.
	if locked.state == nil || locked.state.work != w || locked.state.command != command ||
		locked.state.owner != owner || locked.state.update != update.state {
		return identity.ForbiddenError{}
	}
	return nil
}

// ApplyDirectoryTeamRoleUpdate updates the existing Group contribution and its
// single selected role projection atomically in the original Work. It never
// assigns a native role, changes local memberships or owns audit/outbox/recovery.
// Propagate all errors and call RequireDirectoryTeamRoleUpdate at final commit.
func (r *Repository) ApplyDirectoryTeamRoleUpdate(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryTeamRoleUpdate, locked DirectoryTeamRoleLock) error {
	if r == nil || r.pool == nil || ctx == nil {
		return identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	if err := requireDirectoryTeamRoleLock(w, owner, command, update, locked); err != nil {
		return err
	}
	if locked.state.applied {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	u, p := update.state, locked.state
	i := u.grant.state.input
	if err := r.requireDirectoryTeamGrantTarget(ctx, w, owner, i); err != nil {
		return err
	}
	member, err := readMember(ctx, w, i.Scope.TenantID, i.Scope.OrganizationID, i.Scope.UserID)
	if err != nil {
		return err
	}
	if member != p.member {
		return identity.ForbiddenError{}
	}
	if i.Active {
		version, err := requireDirectoryTeamRoleSelection(ctx, w, u)
		if err != nil {
			return err
		}
		if version != p.roleVersion {
			return identity.ForbiddenError{}
		}
		if err := requireDirectoryTeamRoleCapacity(ctx, w, u); err != nil {
			return err
		}
	}
	if err := r.ApplyDirectoryTeamGrantUpdate(ctx, w, owner, command, u.grant); err != nil {
		return err
	}
	changed, err := persistDirectoryTeamRole(ctx, w, u)
	if err != nil {
		return err
	}
	if changed {
		if p.organizationVersion == math.MaxUint64 || p.member.AuthorizationVersion == math.MaxUint64 {
			return identity.ConflictError{}
		}
		observation := organization.CredentialAuthorityObservation{Actor: p.member}
		if err := r.reconcileProviderRoleAuthorization(ctx, w, observation, true); err != nil {
			return err
		}
		n, err := w.Exec(ctx, advanceDirectoryTeamRoleOrganizationSQL, string(i.Scope.TenantID), string(i.Scope.OrganizationID),
			strconv.FormatUint(p.organizationVersion, 10), strconv.FormatUint(i.CredentialVersion, 10))
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
		p.organizationVersion++
		p.member.AuthorizationVersion++
	}
	p.applied = true
	return r.RequireDirectoryTeamRoleUpdate(ctx, w, owner, command, update, locked)
}

// RequireDirectoryTeamRoleUpdate fences the exact provisional Group and role
// effects, unchanged native member and credential version, and only this Work's
// own policy/authorization successor. It is read-only and valid in final commit,
// not a new admission or a renewable source observation.
func (r *Repository) RequireDirectoryTeamRoleUpdate(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryTeamRoleUpdate, locked DirectoryTeamRoleLock) error {
	if r == nil || r.pool == nil || ctx == nil {
		return identity.ForbiddenError{}
	}
	if err := requireDirectoryTeamRoleLock(w, owner, command, update, locked); err != nil {
		return err
	}
	if !locked.state.applied {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	u, p := update.state, locked.state
	i := u.grant.state.input
	i.OrganizationVersion, i.MemberAuthorizationVersion = p.organizationVersion, p.member.AuthorizationVersion
	if err := r.requireDirectoryTeamGrantTarget(ctx, w, owner, i); err != nil {
		return err
	}
	member, err := readMember(ctx, w, i.Scope.TenantID, i.Scope.OrganizationID, i.Scope.UserID)
	if err != nil {
		return err
	}
	if member != p.member {
		return identity.ForbiddenError{}
	}
	if err := requireDirectoryTeamGrantRow(ctx, w, u.grant); err != nil {
		return err
	}
	if err := requireDirectoryTeamRoleRow(ctx, w, u); err != nil {
		return err
	}
	if i.Active {
		version, err := requireDirectoryTeamRoleSelection(ctx, w, u)
		if err != nil {
			return err
		}
		if version != p.roleVersion {
			return identity.ForbiddenError{}
		}
	}
	return nil
}

// RequireDirectoryTeamRoleSourceOwner verifies the source owner's original
// organization observation after this exact Work's role effect. It substitutes
// only that effect's verified organization successor; credential version and
// freshness stay unchanged. The source owner must still verify its connection,
// provider mapping, and Group edge. Call after RequireDirectoryTeamRoleUpdate.
func (r *Repository) RequireDirectoryTeamRoleSourceOwner(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, source DirectoryTeamRoleSource, original organization.CredentialAuthorityObservation, locked DirectoryTeamRoleLock) error {
	if r == nil || r.pool == nil || ctx == nil || locked.state == nil {
		return identity.ForbiddenError{}
	}
	p := locked.state
	if !p.applied || source != p.update.source {
		return identity.ForbiddenError{}
	}
	if err := requireDirectoryTeamRoleLock(w, owner, command, DirectoryTeamRoleUpdate{state: p.update}, locked); err != nil {
		return err
	}
	i := p.update.grant.state.input
	if original.TenantID != source.Scope.TenantID || original.OrganizationID != source.Scope.OrganizationID ||
		original.Actor != (organization.Member{}) || original.Version != i.OrganizationVersion || original.CredentialVersion != i.CredentialVersion {
		return identity.ForbiddenError{}
	}
	original.Version = p.organizationVersion
	return r.RequireCredentialAuthority(ctx, w, owner, original)
}

const lockDirectoryTeamRoleOrganizationSQL = `SELECT version::text,credential_version::text FROM organization.organizations
WHERE tenant_id=$1 AND organization_id=$2 AND state='active' FOR NO KEY UPDATE`

func requireDirectoryTeamRoleOrganization(ctx context.Context, w kernel.Work, i DirectoryTeamGrantInput, expected uint64) error {
	rows, err := w.Query(ctx, lockDirectoryTeamRoleOrganizationSQL, string(i.Scope.TenantID), string(i.Scope.OrganizationID))
	var version, credential string
	if err := one(rows, err, &version, &credential); err != nil {
		return err
	}
	if version != strconv.FormatUint(expected, 10) || credential != strconv.FormatUint(i.CredentialVersion, 10) {
		return identity.ForbiddenError{}
	}
	return nil
}

const directoryTeamRoleSelectionSQL = `SELECT b.version::text,r.version::text FROM organization.team_role_bindings b
JOIN organization.custom_roles r USING(tenant_id,organization_id,role_id)
WHERE b.tenant_id=$1 AND b.organization_id=$2 AND b.team_id=$3 AND b.role_id=$4 AND b.state='active' AND r.state='active' FOR SHARE OF b,r`

func requireDirectoryTeamRoleSelection(ctx context.Context, w kernel.Work, u *directoryTeamRoleUpdateState) (uint64, error) {
	s := u.source.Scope
	rows, err := w.Query(ctx, directoryTeamRoleSelectionSQL, string(s.TenantID), string(s.OrganizationID), string(s.TeamID), string(u.source.RoleID))
	var binding, role string
	if err := one(rows, err, &binding, &role); err != nil {
		return 0, err
	}
	if binding != strconv.FormatUint(u.bindingVersion, 10) {
		return 0, identity.ForbiddenError{}
	}
	return positive(role)
}

const directoryTeamRoleCapacitySQL = `SELECT count(*),coalesce(bool_or(provider_id=$4 AND connection_id=$5 AND group_id=$6 AND team_id=$7),false)
FROM (SELECT provider_id,connection_id,group_id,team_id FROM organization.directory_team_role_grants
WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 LIMIT 129) d`

func directoryTeamRoleArgs(u *directoryTeamRoleUpdateState) []any {
	s := u.source.Scope
	return []any{string(s.TenantID), string(s.OrganizationID), string(s.UserID), string(s.ProviderID), string(s.ConnectionID), string(s.GroupID), string(s.TeamID)}
}

func requireDirectoryTeamRoleCapacity(ctx context.Context, w kernel.Work, u *directoryTeamRoleUpdateState) error {
	rows, err := w.Query(ctx, directoryTeamRoleCapacitySQL, directoryTeamRoleArgs(u)...)
	var count int64
	var exists bool
	if err := one(rows, err, &count, &exists); err != nil {
		return err
	}
	// The opted-in read profile admits at most 128 source keys. The canonical
	// organization writer lock serializes every admission to that same bound.
	if count > maximumDirectoryTeamRoleSources || !exists && count >= maximumDirectoryTeamRoleSources {
		return identity.ConflictError{}
	}
	return nil
}

const upsertDirectoryTeamRoleSQL = `INSERT INTO organization.directory_team_role_grants
(tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id,member_resource_id,role_id,grant_version,binding_version,provider_version,mapping_version,connection_version)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::numeric,$11::numeric,$12::numeric,$13::numeric,$14::numeric)
ON CONFLICT(tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id) DO UPDATE SET
member_resource_id=EXCLUDED.member_resource_id,role_id=EXCLUDED.role_id,grant_version=EXCLUDED.grant_version,binding_version=EXCLUDED.binding_version,
provider_version=EXCLUDED.provider_version,mapping_version=EXCLUDED.mapping_version,connection_version=EXCLUDED.connection_version`

const deleteDirectoryTeamRoleSQL = `DELETE FROM organization.directory_team_role_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3
AND provider_id=$4 AND connection_id=$5 AND group_id=$6 AND team_id=$7`

func persistDirectoryTeamRole(ctx context.Context, w kernel.Work, u *directoryTeamRoleUpdateState) (bool, error) {
	args := directoryTeamRoleArgs(u)
	if !u.grant.state.input.Active {
		n, err := w.Exec(ctx, deleteDirectoryTeamRoleSQL, args...)
		return n == 1, err
	}
	args = append(args, string(u.source.MemberResourceID), string(u.source.RoleID), strconv.FormatUint(u.grant.AfterVersion(), 10),
		strconv.FormatUint(u.bindingVersion, 10), strconv.FormatUint(u.source.ProviderVersion, 10),
		strconv.FormatUint(u.source.MappingVersion, 10), strconv.FormatUint(u.source.ConnectionVersion, 10))
	n, err := w.Exec(ctx, upsertDirectoryTeamRoleSQL, args...)
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, identity.ConflictError{}
	}
	return true, nil
}

const directoryTeamRoleRowSQL = `SELECT member_resource_id::text,role_id::text,grant_version::text,binding_version::text,provider_version::text,mapping_version::text,connection_version::text
FROM organization.directory_team_role_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3
AND provider_id=$4 AND connection_id=$5 AND group_id=$6 AND team_id=$7 FOR SHARE`

func requireDirectoryTeamRoleRow(ctx context.Context, w kernel.Work, u *directoryTeamRoleUpdateState) error {
	rows, err := w.Query(ctx, directoryTeamRoleRowSQL, directoryTeamRoleArgs(u)...)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := rows.Next()
	if !u.grant.state.input.Active {
		if found {
			return identity.ForbiddenError{}
		}
		return rows.Err()
	}
	if !found {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	var member, role, grant, binding, provider, mapping, connection string
	if err := rows.Scan(&member, &role, &grant, &binding, &provider, &mapping, &connection); err != nil {
		return err
	}
	if rows.Next() {
		return identity.UnavailableError{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if member != string(u.source.MemberResourceID) || role != string(u.source.RoleID) || grant != strconv.FormatUint(u.grant.AfterVersion(), 10) ||
		binding != strconv.FormatUint(u.bindingVersion, 10) || provider != strconv.FormatUint(u.source.ProviderVersion, 10) ||
		mapping != strconv.FormatUint(u.source.MappingVersion, 10) || connection != strconv.FormatUint(u.source.ConnectionVersion, 10) {
		return identity.ForbiddenError{}
	}
	return nil
}

const advanceDirectoryTeamRoleOrganizationSQL = `UPDATE organization.organizations SET version=version+1
WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND credential_version=$4::numeric AND state='active' AND version<18446744073709551615`
