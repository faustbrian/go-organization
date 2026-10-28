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
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestOrganizationGenuineActiveOrganizationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "active-organization")
}

func exerciseGenuineActiveOrganization(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, owner, member organization.Authentication, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, signinMember func() organization.Authentication) {
	t.Helper()
	key := func(raw string) identity.IdempotencyKey {
		k, err := identity.NewIdempotencyKey([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	fresh := func() *organizationpg.OperationService {
		source := consumerOrganizationServiceSelection(t, pool, sessions, profile, lookup, keys, material, organization.DynamicRoleConfig{}, nil, true)
		policy, err := fixtureAuthorization()
		if err != nil {
			t.Fatal(err)
		}
		query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
		requestKeys, err := kernel.NewRequestKeyConfig("organization-selection-consumer", keys["request"], query)
		if err != nil {
			t.Fatal(err)
		}
		custody, err := organizationpg.NewOperationCustodyConfig("selection", map[string][]byte{"selection": material("delivery-envelope")})
		if err != nil {
			t.Fatal(err)
		}
		service, err := organizationpg.NewOperationService(source, organizationpg.OperationServiceConfig{ConfigurationID: "organization-selection-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(ctx context.Context) (organization.ID, error) {
			id, err := identity.NewSubjectID()
			return organization.ID(id), errors.Join(ctx.Err(), err)
		}})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	service := fresh()
	create := func(slug string) organization.ID {
		out, err := service.Create(ctx, organization.CreateOperationRequest{Authentication: owner, IdempotencyKey: key(slug + "-create"), Name: "Published selector consumer", Slug: slug, CorrelationID: slug}, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.OrganizationID == "" {
			t.Fatal("published keyed organization creation", err)
		}
		added, err := service.AddMember(ctx, organization.AddMemberOperationRequest{Authentication: owner, IdempotencyKey: key(slug + "-member"), OrganizationID: out.OrganizationID, UserID: memberID, Role: organization.RoleMember, OrganizationVersion: 1, CorrelationID: slug + "-member"}, "127.0.0.1")
		if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("published keyed membership admission", err)
		}
		return out.OrganizationID
	}
	first, second := create("selected-first"), create("selected-second")
	sibling := signinMember()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization_selected_consumer")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(sessionpg.OrganizationSelectionMigrationSource{Schema: "session_store", Version: 7011}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("public selection migration after genuine sessions/members", err)
	}
	read := func(a organization.Authentication) organization.ActiveOrganizationView {
		view, err := service.GetActiveOrganization(ctx, organization.ActiveOrganizationReadRequest{Authentication: a, CorrelationID: "consumer-current-selection"})
		if err != nil {
			t.Fatal("published current selection", err)
		}
		return view
	}
	a, b := read(member), read(sibling)
	if a.Selected || b.Selected || a.SessionID == "" || b.SessionID == "" || a.SessionID == b.SessionID {
		t.Fatal("two genuine independent sessions did not start unselected")
	}
	original := organization.ActiveOrganizationOperationRequest{Authentication: member, IdempotencyKey: key("consumer-first-selection"), SessionID: a.SessionID, OrganizationID: first, CorrelationID: "consumer-first-selection"}
	committed, err := service.SetActiveOrganization(ctx, original, "127.0.0.1")
	if err != nil || committed.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("published genuine bearer selection", err)
	}
	if view := read(member); !view.Selected || view.Organization.ID != first || view.Member.UserID != memberID || view.SessionVersion != a.SessionVersion+1 {
		t.Fatal("selected organization cannot be used by exact session")
	}
	if view := read(sibling); view.Selected || view.SessionVersion != b.SessionVersion {
		t.Fatal("first choice leaked into sibling session")
	}
	other := organization.ActiveOrganizationOperationRequest{Authentication: sibling, IdempotencyKey: key("consumer-sibling-selection"), SessionID: b.SessionID, OrganizationID: second, CorrelationID: "consumer-sibling-selection"}
	if out, err := service.SetActiveOrganization(ctx, other, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("second genuine session cannot choose independently", err)
	}
	if view := read(member); view.Organization.ID != first {
		t.Fatal("sibling choice changed first session")
	}
	if out, err := fresh().SetActiveOrganization(ctx, original, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, committed) {
		t.Fatal("published fresh-service original-key history", err)
	}
	for _, target := range []organization.ID{second, ""} {
		request := original
		request.IdempotencyKey = key("consumer-selection-" + string(target))
		request.OrganizationID = target
		if out, err := service.SetActiveOrganization(ctx, request, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("published switch/clear", err)
		}
		view := read(member)
		if target == "" {
			if view.Selected || view.Organization != (organization.Organization{}) || view.Member != (organization.Member{}) || view.SessionVersion != a.SessionVersion+3 {
				t.Fatal("explicit clear retained selection")
			}
		} else if !view.Selected || view.Organization.ID != target {
			t.Fatal("switch did not change exact-session target")
		}
	}
	if out, err := fresh().SetActiveOrganization(ctx, original, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, committed) {
		t.Fatal("original key lost history after later selection", err)
	}
	if out, err := fresh().RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: member, Binding: committed.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, committed) {
		t.Fatal("original history lost after later selection", err)
	}
	if view := read(member); view.Selected {
		t.Fatal("original history replayed earlier selection")
	}
	if view := read(sibling); !view.Selected || view.Organization.ID != second || view.SessionVersion != b.SessionVersion+1 {
		t.Fatal("switch/clear changed sibling choice")
	}
	foreign := original
	foreign.Authentication = sibling
	if out, err := fresh().SetActiveOrganization(ctx, foreign, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out != (organization.StoreResult{}) {
		t.Fatal("sibling disclosed original exact-session history", err)
	}
	removed, err := service.RemoveMember(ctx, organization.RemoveMemberOperationRequest{Authentication: owner, OrganizationID: second, UserID: memberID, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "consumer-remove-selected-member"}, "127.0.0.1")
	if err != nil || removed.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual selected membership withdrawal", err)
	}
	if view, err := service.GetActiveOrganization(ctx, organization.ActiveOrganizationReadRequest{Authentication: sibling, CorrelationID: "consumer-withdrawn-selection"}); err == nil || view != (organization.ActiveOrganizationView{}) {
		t.Fatal("removed member retained selected read", err)
	}
	if out, err := fresh().SetActiveOrganization(ctx, other, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" || out.OrganizationID != "" || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("withdrawn authority disclosed original selection history", err)
	}
	if view := read(member); view.Selected {
		t.Fatal("unrelated withdrawal restored cleared selection")
	}
}
