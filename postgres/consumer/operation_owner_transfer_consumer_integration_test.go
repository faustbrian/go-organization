//go:build integration

package consumer_test

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestOrganizationGenuineOwnerTransferOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "owner-transfer-operation")
}

type ownerTransferAdmissionEvaluator struct{}

func (*ownerTransferAdmissionEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && r.Action == authorization.Action(organization.OwnerTransfer) && r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(organization.OwnerTransfer) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}

type genuineOwnerTransferOperation interface {
	OwnerTransfer(context.Context, organization.OwnerTransferOperationRequest, string) (organization.StoreResult, error)
}

// The shared graph issues all human credentials through actual public signup,
// captured verification delivery, confirmation and password signin. Its native
// password owner signs and consumes the real session/action-bound proof.
func exerciseGenuineOwnerTransferOperation(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, owner, member organization.Authentication, ownerID, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, newSource func(*database.Pool) *organizationpg.Service, signinOwner func() organization.Authentication, proof func(organization.Authentication) auth.ReauthenticationProof, logout reference.SessionService) {
	t.Helper()
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-owner-transfer-operation", Revision: 9, Evaluator: new(ownerTransferAdmissionEvaluator)})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
	requestKeys, err := kernel.NewRequestKeyConfig("owner-transfer-operation", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("owner-transfer-operation", map[string][]byte{"owner-transfer-operation": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	build := func(primary *database.Pool) *organizationpg.OperationService {
		t.Helper()
		facade, err := organizationpg.NewOperationService(newSource(primary), organizationpg.OperationServiceConfig{ConfigurationID: "owner-transfer-operation-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) {
			t.Error("owner transfer allocated another organization")
			return "", organization.ErrUnavailable
		}})
		if err != nil {
			t.Fatal(err)
		}
		return facade
	}
	invoke := func(primary *database.Pool, r organization.OwnerTransferOperationRequest) (organization.StoreResult, error) {
		t.Helper()
		operation, ok := any(build(primary)).(genuineOwnerTransferOperation)
		if !ok {
			t.Fatal("genuine original-key owner-transfer operation missing")
		}
		return operation.OwnerTransfer(ctx, r, "127.0.0.1")
	}
	source := newSource(pool)
	create := func(label string) organization.ID {
		t.Helper()
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		org := organization.ID(id)
		commit := func(p organizationpg.PreparedCommand, err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
			out, err := source.Execute(ctx, p)
			if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("genuine transfer setup", err)
			}
		}
		commit(source.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Original keyed ownership", Slug: "keyed-transfer-" + label, CorrelationID: "transfer-setup"}, "127.0.0.1"))
		commit(source.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: organization.RoleMember, CorrelationID: "transfer-setup"}, "127.0.0.1"))
		return org
	}
	request := func(org organization.ID, label string) organization.OwnerTransferOperationRequest {
		t.Helper()
		key, err := identity.NewIdempotencyKey([]byte("genuine-original-transfer-" + label))
		if err != nil {
			t.Fatal(err)
		}
		return organization.OwnerTransferOperationRequest{Authentication: owner, IdempotencyKey: key, OrganizationID: org, TargetUserID: memberID, OrganizationVersion: 2, SourceVersion: 1, TargetVersion: 1, CorrelationID: "original-transfer", Proof: proof(owner)}
	}
	assertState := func(org organization.ID, transferred bool) {
		t.Helper()
		var epoch, sourceVersion, targetVersion, sourceAuthority, targetAuthority, owners, members, effects int
		var sourceRole, targetRole string
		err := db.QueryRowContext(ctx, `SELECT o.version::integer,o.owner_count,o.member_count,a.role,a.version::integer,a.authorization_version::integer,b.role,b.version::integer,b.authorization_version::integer,(SELECT count(*) FROM organization.command_effects e WHERE e.tenant_id=o.tenant_id AND e.organization_id=o.organization_id AND e.operation='identity.organization.owner-transfer') FROM organization.organizations o JOIN organization.memberships a USING(tenant_id,organization_id) JOIN organization.memberships b USING(tenant_id,organization_id) WHERE o.tenant_id=$1 AND o.organization_id=$2 AND a.user_id=$3 AND b.user_id=$4`, string(owner.TenantID), string(org), string(ownerID), string(memberID)).Scan(&epoch, &owners, &members, &sourceRole, &sourceVersion, &sourceAuthority, &targetRole, &targetVersion, &targetAuthority, &effects)
		wantEpoch, wantVersion, wantEffects := 2, 1, 0
		wantSource, wantTarget := "owner", "member"
		if transferred {
			wantEpoch, wantVersion, wantEffects = 3, 2, 1
			wantSource, wantTarget = "member", "owner"
		}
		if err != nil || epoch != wantEpoch || owners != 1 || members != 2 || sourceVersion != wantVersion || targetVersion != wantVersion || sourceAuthority != wantVersion || targetAuthority != wantVersion || sourceRole != wantSource || targetRole != wantTarget || effects != wantEffects {
			t.Fatal("genuine keyed transfer role/authority/effect atomicity", err)
		}
	}
	org := create("original")
	r := request(org, "original")
	original, err := invoke(pool, r)
	if err != nil || original.Receipt.Validate() != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted || original.Receipt.Binding.ActorID != identity.ActorID(ownerID) || original.MemberID != memberID || original.Receipt.Feature.BeforeVersion != 2 || original.Receipt.Feature.AfterVersion != 3 {
		t.Fatal("genuine original transfer did not commit", err)
	}
	assertState(org, true)
	fresh := signinOwner()
	if fresh.Bearer.Token() == owner.Bearer.Token() {
		t.Fatal("recovery reused original credential")
	}
	r.Authentication = fresh
	r.CorrelationID = "retry-keeps-original"
	for range 2 {
		got, err := invoke(pool, r)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("genuine former-owner original-key recovery", err)
		}
	}
	if got, err := build(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: fresh, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal("fresh genuine former-owner explicit history", err)
	}
	changed := r
	changed.TargetVersion++
	if _, err := invoke(pool, changed); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("changed original transfer intent admitted", err)
	}
	view, err := source.ListMembers(ctx, organization.ReadRequest{Authentication: member, OrganizationID: org, Limit: 10, CorrelationID: "new-owner"})
	if err != nil || view.Actor.Role != organization.RoleOwner || view.Actor.Version != 2 {
		t.Fatal("genuine new owner lacks authority", err)
	}
	if _, err := source.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: member, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 3, UserID: memberID, MemberVersion: 2, CorrelationID: "last-owner"}, "127.0.0.1"); !errors.Is(err, organization.ErrLastOwner) {
		t.Fatal("genuine transferred last owner removable", err)
	}
	newKey, err := identity.NewIdempotencyKey([]byte("former-owner-no-new-authority"))
	if err != nil {
		t.Fatal(err)
	}
	forbidden := r
	forbidden.IdempotencyKey, forbidden.Proof = newKey, proof(fresh)
	forbidden.OrganizationVersion, forbidden.SourceVersion, forbidden.TargetVersion = 3, 2, 2
	if _, err := invoke(pool, forbidden); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("genuine former owner retained transfer privilege", err)
	}
	for _, mappingOnly := range []bool{true, false} {
		label := "domain-loss"
		if mappingOnly {
			label = "mapping-loss"
		}
		t.Run(label, func(t *testing.T) {
			org := create(label)
			r := request(org, label)
			fault := new(commitResponseLoss)
			primary, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
					if err != nil {
						return nil, err
					}
					return &lossyCommitConn{Conn: conn, fault: fault}, nil
				}
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := primary.Close(cleanup); err != nil {
					t.Error(err)
				}
			}()
			fault.count.Store(-1)
			if mappingOnly {
				fault.count.Store(1)
			}
			fault.armed.Store(true)
			out, err := invoke(primary, r)
			if err == nil || !fault.lost.Load() || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.Receipt.Binding.CommandID == "" {
				t.Fatal("genuine COMMIT loss lost original scope", err)
			}
			for range 2 {
				got, err := invoke(pool, r)
				var unknown identity.UnknownCommitError
				if got.Receipt.Binding != out.Receipt.Binding || mappingOnly && (!errors.As(err, &unknown) || got.Receipt.Outcome != identity.CommitOutcomeUnknown) || !mappingOnly && (err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted) {
					t.Fatal("genuine unknown outcome caused replacement execution", err)
				}
			}
			assertState(org, !mappingOnly)
		})
	}
	token, err := session.ParseToken(fresh.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	signedOut, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: fresh.TenantID, CommandID: commandID(t), CorrelationID: "transfer-signout", Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{})
	if err != nil || !signedOut.SignedOut || signedOut.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine transfer source logout", err)
	}
	if _, err := invoke(pool, r); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("logged-out former owner recovered transfer", err)
	}
	if _, err := source.Get(ctx, organization.ReadRequest{Authentication: member, OrganizationID: org, CorrelationID: "independent-new-owner"}); err != nil {
		t.Fatal("former owner logout revoked independent new owner", err)
	}
}
