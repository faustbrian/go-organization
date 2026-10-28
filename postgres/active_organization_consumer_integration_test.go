//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func (f *activeOrganizationFixture) native(t *testing.T, pool *database.Pool) *organizationpg.Service {
	t.Helper()
	return selectionOrganizationService(t, pool, f.sessions, f.profile, f.lookup, f.keys, f.material)
}

func (f *activeOrganizationFixture) operations(t *testing.T, pool *database.Pool) *organizationpg.OperationService {
	t.Helper()
	policy, err := fixtureAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	return f.operationsFromSource(t, pool, f.native(t, pool), policy)
}

func (f *activeOrganizationFixture) operationsFromSource(t *testing.T, pool *database.Pool, source *organizationpg.Service, policy authorization.Service) *organizationpg.OperationService {
	t.Helper()
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
	keys, err := kernel.NewRequestKeyConfig("organization-selection-consumer", f.keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("selection", map[string][]byte{"selection": f.material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	service, err := organizationpg.NewOperationService(source, organizationpg.OperationServiceConfig{ConfigurationID: "organization-selection-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: f.keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: keys, Custody: custody, NewOrganizationID: func(ctx context.Context) (organization.ID, error) {
		id, err := identity.NewSubjectID()
		return organization.ID(id), errors.Join(ctx.Err(), err)
	}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func (f *activeOrganizationFixture) record(t *testing.T, a organization.Authentication) session.SessionSpec {
	t.Helper()
	token, err := session.ParseToken(a.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: a.TenantID, Credential: credential})
	if err != nil || result.ValidateAt(time.Now()) != nil {
		t.Fatal("actual native bearer read", err)
	}
	spec, err := result.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func selectionKey(t *testing.T, raw string) identity.IdempotencyKey {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (f *activeOrganizationFixture) create(t *testing.T, slug string) organization.ID {
	t.Helper()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org := organization.ID(id)
	service := f.native(t, f.pool)
	command, err := service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: f.owner, CommandID: commandID(t), ID: org, Slug: slug, Name: "Actual selection consumer", CorrelationID: slug}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(f.ctx, command)
	if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual organization creation", err)
	}
	command, err = service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: org, UserID: f.memberID, Role: organization.RoleMember, OrganizationVersion: 1, CorrelationID: slug + "-member"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	result, err = service.Execute(f.ctx, command)
	if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual membership admission", err)
	}
	return org
}

func TestOrganizationGenuineBearerSelection(t *testing.T) {
	f := newActiveOrganizationFixture(t)
	f.requireSupportedSelectionCounterProfile(t)
	first, second := f.create(t, "selected-first"), f.create(t, "selected-second")
	sibling := f.signinMember()
	before, otherBefore := f.record(t, f.member), f.record(t, sibling)
	f.installSelectionPreservingPopulatedRows(t)
	assertFamilyUnchanged := f.sameFamilySibling(t, before)
	if before.SessionID == otherBefore.SessionID || before.FamilyID == otherBefore.FamilyID {
		t.Fatal("genuine distinct sessions/families required")
	}
	service := f.operations(t, f.pool)
	cookieBefore := f.record(t, f.cookieMember)
	if _, err := f.native(t, f.pool).Get(f.ctx, organization.ReadRequest{Authentication: f.cookieMember, OrganizationID: first, CorrelationID: "ordinary-cookie-compatible"}); err != nil {
		t.Fatal("existing ordinary organization cookie compatibility", err)
	}
	if view, err := service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: f.cookieMember, CorrelationID: "unsupported-cookie"}); !errors.Is(err, organization.ErrForbidden) || view != (organization.ActiveOrganizationView{}) {
		t.Fatal("cookie selection did not fail closed", err)
	}
	if _, err := f.native(t, f.pool).PrepareActiveOrganization(f.ctx, organization.ActiveOrganizationRequest{Authentication: f.cookieMember, CommandID: commandID(t), SessionID: cookieBefore.SessionID, OrganizationID: first, CorrelationID: "unsupported-cookie-set"}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("cookie was stripped into bearer selection", err)
	}
	for _, a := range []organization.Authentication{sibling, f.owner} {
		if _, err := f.native(t, f.pool).PrepareActiveOrganization(f.ctx, organization.ActiveOrganizationRequest{Authentication: a, CommandID: commandID(t), SessionID: before.SessionID, OrganizationID: first, CorrelationID: "foreign-session"}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("foreign exact session accepted", err)
		}
	}
	foreign := f.member
	foreign.TenantID = "different-tenant"
	if view, err := service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: foreign, CorrelationID: "foreign-tenant"}); err == nil || view != (organization.ActiveOrganizationView{}) {
		t.Fatal("foreign tenant disclosed selection", err)
	}
	for _, a := range []organization.Authentication{f.member, sibling} {
		view, err := service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: a, CorrelationID: "initial-unselected"})
		if err != nil || view.Selected {
			t.Fatal("genuine session did not start unselected", err)
		}
	}
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := fixtureAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	core, err := organization.NewActiveOrganizationService(f.sessions, repository, policy, organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		_, err := identity.ParseSubjectID(string(id))
		return errors.Join(ctx.Err(), err)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = core.PrepareActiveSet(f.ctx, organization.ActiveOrganizationRequest{Authentication: f.member, CommandID: commandID(t), SessionID: before.SessionID, OrganizationID: first, CorrelationID: "root-admission-probe"}); err != nil {
		t.Fatal("root actual session/target/policy admission", err)
	}
	if _, err := f.native(t, f.pool).PrepareActiveOrganization(f.ctx, organization.ActiveOrganizationRequest{Authentication: f.member, CommandID: commandID(t), SessionID: before.SessionID, OrganizationID: first, CorrelationID: "direct-admission-probe"}, "127.0.0.1"); err != nil {
		t.Fatal("direct public selector preparation", err)
	}
	request := organization.ActiveOrganizationOperationRequest{Authentication: f.member, IdempotencyKey: selectionKey(t, "first-selection-original"), SessionID: before.SessionID, OrganizationID: first, CorrelationID: "first-selection"}
	result, err := service.SetActiveOrganization(f.ctx, request, "127.0.0.1")
	if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual bearer selection did not commit", err)
	}
	siblingHistory := request
	siblingHistory.Authentication = sibling
	if out, err := service.SetActiveOrganization(f.ctx, siblingHistory, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out != (organization.StoreResult{}) {
		t.Fatal("sibling obtained exact-session original-key history", err)
	}
	f.exerciseSelectionHistoryPolicy(t, request, result)
	view, err := service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: f.member, CorrelationID: "selected-read"})
	if err != nil || !view.Selected || view.Organization.ID != first || view.Member.UserID != f.memberID || view.SessionID != before.SessionID || view.SessionVersion != before.Version+1 {
		t.Fatal("exact-session selected organization not usable", err)
	}
	other, err := service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: sibling, CorrelationID: "sibling-read"})
	if err != nil || other.Selected || other.SessionID != otherBefore.SessionID {
		t.Fatal("selection leaked to sibling/family", err)
	}
	after := f.record(t, f.member)
	if after.Authentication != before.Authentication || after.Remember != before.Remember || !after.IssuedAt.Equal(before.IssuedAt) || !after.LastActivityAt.Equal(before.LastActivityAt) || after.Lookup != before.Lookup || after.FamilyID != before.FamilyID || after.FamilyVersion != before.FamilyVersion {
		t.Fatal("selection renewed authentication, lifetime, token or family")
	}
	if got := f.record(t, sibling); !reflect.DeepEqual(got, otherBefore) {
		t.Fatal("sibling session changed")
	}
	siblingRequest := organization.ActiveOrganizationOperationRequest{Authentication: sibling, IdempotencyKey: selectionKey(t, "sibling-selection-original"), SessionID: otherBefore.SessionID, OrganizationID: second, CorrelationID: "sibling-selection"}
	if out, err := service.SetActiveOrganization(f.ctx, siblingRequest, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("second genuine session cannot select independently", err)
	}
	if view, err := service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: f.member, CorrelationID: "first-still-independent"}); err != nil || view.Organization.ID != first {
		t.Fatal("sibling choice changed first selection", err)
	}
	retry, err := f.operations(t, f.pool).SetActiveOrganization(f.ctx, request, "127.0.0.1")
	if err != nil || !reflect.DeepEqual(result, retry) {
		t.Fatal("fresh service original-key recovery changed history", err)
	}
	request.IdempotencyKey = selectionKey(t, "second-selection-original")
	request.OrganizationID = second
	request.CorrelationID = "switch-selection"
	switched, err := service.SetActiveOrganization(f.ctx, request, "127.0.0.1")
	if err != nil || switched.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual selection switch", err)
	}
	oldRequest := request
	oldRequest.IdempotencyKey = selectionKey(t, "first-selection-original")
	oldRequest.OrganizationID = first
	replay, err := f.operations(t, f.pool).SetActiveOrganization(f.ctx, oldRequest, "127.0.0.1")
	if err != nil || !reflect.DeepEqual(result, replay) {
		t.Fatal("historical key could not recover after switch", err)
	}
	view, err = service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: f.member, CorrelationID: "switch-read"})
	if err != nil || view.Organization.ID != second {
		t.Fatal("old key replayed prior selection", err)
	}
	request.IdempotencyKey = selectionKey(t, "clear-selection-original")
	request.OrganizationID = ""
	request.CorrelationID = "clear-selection"
	cleared, err := service.SetActiveOrganization(f.ctx, request, "127.0.0.1")
	if err != nil || cleared.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("explicit clear", err)
	}
	view, err = service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: f.member, CorrelationID: "clear-read"})
	if err != nil || view.Selected || view.Organization != (organization.Organization{}) || view.Member != (organization.Member{}) || view.SessionVersion != before.Version+3 {
		t.Fatal("clear retained selection", err)
	}
	if other, err := service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: sibling, CorrelationID: "sibling-after-clear"}); err != nil || !other.Selected || other.Organization.ID != second || other.SessionVersion != otherBefore.Version+1 {
		t.Fatal("first session clear changed sibling/family choice", err)
	}
	clearedSpec := f.record(t, f.member)
	if clearedSpec.Authentication != before.Authentication || clearedSpec.Remember != before.Remember || clearedSpec.Lookup != before.Lookup || !clearedSpec.IssuedAt.Equal(before.IssuedAt) || !clearedSpec.LastActivityAt.Equal(before.LastActivityAt) || clearedSpec.FamilyVersion != before.FamilyVersion {
		t.Fatal("switch/clear or original-key recovery renewed session authentication/lifetime")
	}
	f.exerciseSelectionCASAndRollback(t, first, second)
	f.exerciseSelectionCancellation(t, second)
	f.exerciseSelectionCommitLoss(t, first, second)
	f.exerciseSelectionIdenticalKeyContention(t, second)
	assertFamilyUnchanged()
	f.exerciseSelectionOriginalDeadline(t, first)
	f.exerciseSelectionAuthorityWithdrawal(t, first, second)
}

func (f *activeOrganizationFixture) exerciseSelectionOriginalDeadline(t *testing.T, target organization.ID) {
	t.Helper()
	service := f.native(t, f.pool)
	before := f.record(t, f.owner)
	prepared, err := service.PrepareActiveOrganization(f.ctx, organization.ActiveOrganizationRequest{Authentication: f.owner, CommandID: commandID(t), SessionID: before.SessionID, OrganizationID: target, CorrelationID: "original-exclusive-deadline"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// The native effect uses primary time. Waiting beyond the maximum original
	// 20-second fence proves a subsequent current read cannot renew the prepared
	// command; the exact exclusive boundary is independently covered in core.
	timer := time.NewTimer(20*time.Second + 5*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("bounded original deadline fixture expired")
	}
	if _, err := service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: f.owner, CorrelationID: "fresh-read-is-not-renewal"}); err != nil {
		t.Fatal(err)
	}
	if result, err := service.Execute(f.ctx, prepared); err == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("fresh read renewed expired original selection command", err)
	}
	if got := f.record(t, f.owner); !reflect.DeepEqual(got, before) {
		t.Fatal("expired selection changed original session/lifetime")
	}
}

func (f *activeOrganizationFixture) exerciseSelectionCASAndRollback(t *testing.T, first, second organization.ID) {
	t.Helper()
	service := f.native(t, f.pool)
	current := f.record(t, f.member)
	prepare := func(target organization.ID) organizationpg.PreparedCommand {
		p, err := service.PrepareActiveOrganization(f.ctx, organization.ActiveOrganizationRequest{Authentication: f.member, CommandID: commandID(t), SessionID: current.SessionID, OrganizationID: target, CorrelationID: "native-cas"}, "127.0.0.1")
		if err != nil {
			t.Fatal("prepare genuine native CAS", err)
		}
		return p
	}
	left, right := prepare(first), prepare(second)
	type casResult struct {
		out organization.StoreResult
		err error
	}
	results := make(chan casResult, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for _, p := range []organizationpg.PreparedCommand{left, right} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			out, err := service.Execute(f.ctx, p)
			results <- casResult{out, err}
		}()
	}
	close(start)
	workers.Wait()
	wins := 0
	for range 2 {
		result := <-results
		if result.err == nil && result.out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			wins++
		} else if result.err == nil || result.out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("stale concurrent CAS had contradictory outcome", result.err)
		}
	}
	if wins != 1 {
		t.Fatal("distinct frozen intents did not have one CAS winner")
	}
	if got := f.record(t, f.member); got.Version != current.Version+1 {
		t.Fatal("stale CAS advanced original version twice")
	}
	for _, boundary := range []string{"audit", "outbox", "cancel", "late-epoch"} {
		before := f.record(t, f.member)
		p := prepare(second)
		recovery, err := p.Recovery()
		if err != nil {
			t.Fatal(err)
		}
		ctx := f.ctx
		if boundary == "cancel" {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		} else {
			table, condition := "audit.records", "NEW.action='identity.organization.active-set' AND NEW.outcome=1"
			if boundary == "outbox" {
				table, condition = "public.identity_outbox_bindings", "true"
			}
			statement := `RAISE EXCEPTION 'controlled required selection effect';`
			if boundary == "late-epoch" {
				statement = `UPDATE organization.organizations SET version=version+1 WHERE organization_id='` + string(second) + `';`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.fail_selection() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN `+statement+` END IF; RETURN NEW; END $$; CREATE TRIGGER fail_selection BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.fail_selection()`); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER IF EXISTS fail_selection ON `+table+`;DROP FUNCTION IF EXISTS organization.fail_selection()`)
				if err != nil {
					t.Error(err)
				}
			}()
		}
		out, err := service.Execute(ctx, p)
		if boundary != "cancel" {
			table := "audit.records"
			if boundary == "outbox" {
				table = "public.identity_outbox_bindings"
			}
			if _, cleanup := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fail_selection ON `+table+`;DROP FUNCTION organization.fail_selection()`); cleanup != nil {
				t.Fatal(cleanup)
			}
		}
		if err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("required effect/cancellation committed selection", boundary)
		}
		if got := f.record(t, f.member); !reflect.DeepEqual(got, before) {
			t.Fatal("failed required effect changed session/family", boundary)
		}
		var effects, audits, outboxes int
		raw, decodeErr := base64.RawURLEncoding.DecodeString(string(recovery.Binding.CommandID))
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM session_store.organization_selections WHERE command_id=$1),
		(SELECT count(*) FROM audit.records a JOIN audit.identity_command_bindings b ON b.event_id=a.record_id WHERE b.command_id=$1 AND a.outcome=1),
		(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, raw).Scan(&effects, &audits, &outboxes); err != nil || effects != 0 || audits != 0 || outboxes != 0 {
			t.Fatal("failed command retained successful selection/audit/outbox effects", boundary, err)
		}
	}
}
