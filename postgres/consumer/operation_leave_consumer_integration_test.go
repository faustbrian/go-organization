//go:build integration

package consumer_test

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOrganizationGenuineSelfLeaveOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "self-leave-operation")
}

// All human credentials come from the public signup/captured-verification/
// password-signin graph. Native domain stores and protected transactions remain
// real; the application supplies only ordinary configuration and policy.
func exerciseGenuineSelfLeaveOperation(t *testing.T, ctx context.Context, db *sql.DB, source *organizationpg.Service, owner, member organization.Authentication, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, freshSource func() *organizationpg.Service, signinMember func() organization.Authentication, logout reference.SessionService) {
	t.Helper()
	steps, err := (organizationpg.LeaveOperationLookupTransactionalMigrationSource{Version: 1}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization_self_leave_operation")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(steps), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("native self-leave lookup installation", err)
	}
	policy, err := fixtureAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
	requestKeys, err := kernel.NewRequestKeyConfig("self-leave-consumer", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("self-leave", map[string][]byte{"self-leave": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	build := func(source *organizationpg.Service) *organizationpg.OperationService {
		t.Helper()
		facade, err := organizationpg.NewOperationService(source, organizationpg.OperationServiceConfig{ConfigurationID: "self-leave-consumer-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) {
			t.Error("self-leave allocated an organization")
			return "", organization.ErrUnavailable
		}})
		if err != nil {
			t.Fatal(err)
		}
		return facade
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org := organization.ID(id)
	commit := func(prepared organizationpg.PreparedCommand, err error) {
		t.Helper()
		if err != nil {
			t.Fatal("genuine self-leave setup", err)
		}
		if out, err := source.Execute(ctx, prepared); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine self-leave setup commit", err)
		}
	}
	commit(source.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Natural self-leave", Slug: "natural-self-leave", CorrelationID: "self-leave-create"}, "127.0.0.1"))
	commit(source.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: organization.RoleMember, CorrelationID: "self-leave-admit"}, "127.0.0.1"))
	request := organization.LeaveMemberOperationRequest{Authentication: member, OrganizationID: org, OrganizationVersion: 2, CorrelationID: "self-leave-original"}
	original, err := build(source).LeaveMember(ctx, request, "127.0.0.1")
	if err != nil || original.Receipt.Validate() != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted || original.OrganizationID != org || original.MemberID != memberID || original.Receipt.Feature == nil || original.Receipt.Feature.BeforeVersion != 2 || original.Receipt.Feature.AfterVersion != 3 || original.Receipt.Binding.UserID != memberID || string(original.Receipt.Binding.ActorID) != string(memberID) {
		t.Fatal("genuine native self-leave did not commit exact self transition", err)
	}
	request.CorrelationID = "self-leave-retry"
	if repeated, err := build(freshSource()).LeaveMember(ctx, request, "127.0.0.1"); err != nil || !reflect.DeepEqual(repeated, original) {
		t.Fatal("natural repeat did not recover actual original leave", err)
	}
	read := organization.ReadRequest{Authentication: member, OrganizationID: org, CorrelationID: "self-leave-read"}
	if _, err := source.Get(ctx, read); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("departed member retained scoped read", err)
	}
	if _, err := source.Recover(ctx, member, organizationpg.Recovery{Binding: original.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("new facade weakened legacy membership recovery", err)
	}
	fresh := signinMember()
	if fresh.Bearer.Token() == member.Bearer.Token() {
		t.Fatal("self-history recovery reused original session")
	}
	recovery := organization.OperationRecoveryRequest{Authentication: fresh, Binding: original.Receipt.Binding}
	if recovered, err := build(freshSource()).RecoverOperation(ctx, recovery); err != nil || !reflect.DeepEqual(recovered, original) {
		t.Fatal("fresh verified departed self could not recover original metadata", err)
	}
	wrong := recovery
	wrong.Authentication = owner
	if out, err := build(source).RecoverOperation(ctx, wrong); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("another human recovered departed self history")
	}
	var effects int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND operation=$3`, string(owner.TenantID), string(org), string(organization.LeaveMember)).Scan(&effects); err != nil || effects != 1 {
		t.Fatal("natural retry duplicated protected self-leave effects", err)
	}
	commit(source.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 3, UserID: memberID, MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "self-leave-readmit"}, "127.0.0.1"))
	if out, err := build(freshSource()).LeaveMember(ctx, request, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("old natural intent became a new membership leave", err)
	}
	read.Authentication = fresh
	if view, err := source.Get(ctx, read); err != nil || view.Actor.UserID != memberID || !view.Actor.Active || view.Actor.Version != 3 {
		t.Fatal("old intent removed the readmitted membership", err)
	}
	if recovered, err := build(freshSource()).RecoverOperation(ctx, recovery); err != nil || !reflect.DeepEqual(recovered, original) {
		t.Fatal("historical self metadata became a mutation after readmission", err)
	}
	lastOwner := request
	lastOwner.Authentication, lastOwner.OrganizationVersion = owner, 4
	if _, err := build(source).LeaveMember(ctx, lastOwner, "127.0.0.1"); !errors.Is(err, organization.ErrLastOwner) {
		t.Fatal("final genuine owner departed", err)
	}
	token, err := session.ParseToken(fresh.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	signedOut, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: fresh.TenantID, CommandID: commandID(t), CorrelationID: "self-leave-signout", Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{})
	if err != nil || !signedOut.SignedOut || signedOut.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual self-history session signout failed", err)
	}
	if out, err := build(freshSource()).RecoverOperation(ctx, recovery); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("revoked human recovered original self-history")
	}
	read.Authentication = owner
	if _, err := source.Get(ctx, read); err != nil {
		t.Fatal("member signout withdrew independent owner", err)
	}
}
