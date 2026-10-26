//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

const metadataOrganization organization.ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

func metadataRequest(t *testing.T, f *orgFixture, tenant, actor string, version uint64) organization.UpdateRequest {
	t.Helper()
	return organization.UpdateRequest{Authentication: f.auth(tenant, actor), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: version, Name: "Updated metadata", Slug: "updated", CorrelationID: "metadata-update"}
}

func assertMetadata(t *testing.T, f *orgFixture, tenant, name, slug, version string, effects int) {
	t.Helper()
	var actualName, actualSlug, actualVersion string
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT name,slug,version::text,(SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.update') FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2`, tenant, string(metadataOrganization)).Scan(&actualName, &actualSlug, &actualVersion, &count); err != nil || actualName != name || actualSlug != slug || actualVersion != version || count != effects {
		t.Fatal("metadata/version/effects differ from atomic expectation", err, actualVersion, count)
	}
}

func TestOrganizationMetadataUpdate(t *testing.T) {
	f := newOrgFixture(t)
	t.Run("owner_admin_replay_and_noop", func(t *testing.T) {
		tenant := "org-test-basic"
		f.create(t, tenant)
		f.add(t, tenant, "second", organization.RoleAdministrator, 1)
		for i, actor := range []string{"owner", "second"} {
			r := metadataRequest(t, f, tenant, actor, uint64(i+2))
			if i == 1 {
				r.Name, r.Slug = "Administrator update", "admin-updated"
			}
			p, err := f.service.PrepareUpdate(f.ctx, r, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				got, err := f.service.Execute(f.ctx, p)
				if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.BeforeVersion != uint64(i+2) || got.Receipt.Feature.AfterVersion != uint64(i+3) {
					t.Fatal("metadata mutation/replay failed", err)
				}
			}
			view, err := f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, actor), OrganizationID: metadataOrganization, CorrelationID: "metadata-update"})
			if err != nil || view.Organization.Name != r.Name || view.Organization.Slug != r.Slug || view.Organization.Version != uint64(i+3) {
				t.Fatal("committed metadata receipt did not match primary read", err)
			}
			recovery, err := p.Recovery()
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.service.Recover(f.ctx, f.auth(tenant, actor), recovery)
			if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != recovery.Binding {
				t.Fatal("historical metadata recovery failed", err)
			}
		}
		assertMetadata(t, f, tenant, "Administrator update", "admin-updated", "4", 2)
		r := metadataRequest(t, f, tenant, "second", 4)
		r.Name, r.Slug = "Administrator update", "admin-updated"
		if _, err := f.service.PrepareUpdate(f.ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("identical metadata created transition", err)
		}
		r.OrganizationVersion = 3
		if _, err := f.service.PrepareUpdate(f.ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("stale version admitted", err)
		}
		var members, unchanged int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE version=1 AND authorization_version=1 AND state='active') FROM organization.memberships WHERE tenant_id=$1`, tenant).Scan(&members, &unchanged); err != nil || members != 2 || unchanged != 2 {
			t.Fatal("metadata changed membership authority", err)
		}
		var events int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND m.topic='organization.updated.v1'`, tenant).Scan(&events); err != nil || events != 2 {
			t.Fatal("metadata lifecycle missing or replayed", err)
		}
		var audits int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND r.action='identity.organization.update'`, tenant).Scan(&audits); err != nil || audits != 2 {
			t.Fatal("metadata audit missing or replayed", err)
		}
	})
	t.Run("collision_and_concurrent_expected_version", func(t *testing.T) {
		tenant := "org-test-race"
		f.create(t, tenant)
		other, err := f.service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Slug: "occupied", Name: "Other", CorrelationID: "metadata-other"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := f.service.Execute(f.ctx, other); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal(err)
		}
		r := metadataRequest(t, f, tenant, "owner", 1)
		r.Slug = "occupied"
		collision, err := f.service.PrepareUpdate(f.ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := f.service.Execute(f.ctx, collision); !errors.Is(err, organization.ErrConflict) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("slug collision escaped conflict rollback", err, got.Receipt.Outcome)
		}
		assertMetadata(t, f, tenant, "Example", "example", "1", 0)
		r = metadataRequest(t, f, tenant, "owner", 1)
		first, err := f.service.PrepareUpdate(f.ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		r.CommandID = commandID(t)
		r.Name, r.Slug = "Losing update", "losing"
		stale, err := f.service.PrepareUpdate(f.ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := f.service.Execute(f.ctx, first); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal(err)
		}
		if got, err := f.service.Execute(f.ctx, stale); !errors.Is(err, organization.ErrConflict) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("prepared stale organization updated", err)
		}
		assertMetadata(t, f, tenant, "Updated metadata", "updated", "2", 1)
	})
	t.Run("unauthorized_cross_tenant_and_withdrawn_membership", func(t *testing.T) {
		tenant := "org-test-scope"
		f.create(t, tenant)
		f.add(t, tenant, "member", organization.RoleMember, 1)
		f.add(t, tenant, "second", organization.RoleAdministrator, 2)
		for _, actor := range []string{"member", "outsider"} {
			if _, err := f.service.PrepareUpdate(f.ctx, metadataRequest(t, f, tenant, actor, 3), "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
				t.Fatal("nonadministrator admitted", err)
			}
		}
		r := metadataRequest(t, f, tenant, "owner", 3)
		r.Authentication.TenantID = "org-test-basic"
		if _, err := f.service.PrepareUpdate(f.ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("cross-tenant bearer admitted", err)
		}
		pending, err := f.service.PrepareUpdate(f.ctx, metadataRequest(t, f, tenant, "second", 3), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		remove, err := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, UserID: "second", OrganizationVersion: 3, MemberVersion: 1, CorrelationID: "withdraw"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := f.service.Execute(f.ctx, remove); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal(err)
		}
		if got, err := f.service.Execute(f.ctx, pending); err == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("removed administrator committed", err)
		}
		assertMetadata(t, f, tenant, "Example", "example", "4", 0)
		recovery, err := pending.Recovery()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.Recover(f.ctx, f.auth(tenant, "second"), recovery); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("removed actor recovered protected update", err)
		}
	})
	t.Run("late_session_and_policy_epoch_withdrawal", func(t *testing.T) {
		for _, tenant := range []string{"org-test-target", "org-test-unknown"} {
			f.create(t, tenant)
			p, err := f.service.PrepareUpdate(f.ctx, metadataRequest(t, f, tenant, "owner", 1), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			if tenant == "org-test-target" {
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='owner'`, tenant)
			} else {
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id=$1 AND policy_namespace='users' AND subject_id='owner'`, tenant)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := f.service.Execute(f.ctx, p); err == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("withdrawn current authority committed", err, got.Receipt.Outcome)
			}
			assertMetadata(t, f, tenant, "Example", "example", "1", 0)
		}
	})
	t.Run("atomic_lifecycle_failure_rollback", func(t *testing.T) {
		tenant := "org-test-rollback"
		f.create(t, tenant)
		p, err := f.service.PrepareUpdate(f.ctx, metadataRequest(t, f, tenant, "owner", 1), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.metadata_fail_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic lifecycle failure'; END $$; CREATE TRIGGER metadata_fail_lifecycle BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.metadata_fail_lifecycle()`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := f.service.Execute(f.ctx, p)
		if err == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("failed lifecycle retained metadata", err)
		}
		if _, err = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER metadata_fail_lifecycle ON public.identity_outbox_bindings; DROP FUNCTION public.metadata_fail_lifecycle()`); err != nil {
			t.Fatal(err)
		}
		assertMetadata(t, f, tenant, "Example", "example", "1", 0)
		got, err = f.service.Execute(f.ctx, p)
		if err != nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("aborted replay repeated mutation", err)
		}
	})
}

func TestOrganizationMetadataUnknownCommitRecovery(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-unknown"
	f.create(t, tenant)
	service, fault := f.lostCommitService(t)
	p, err := service.PrepareUpdate(f.ctx, metadataRequest(t, f, tenant, "owner", 1), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := p.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	fault.armed.Store(true)
	got, err := service.Execute(f.ctx, p)
	if !fault.lost.Load() || err == nil || got.Receipt.Outcome != identity.CommitOutcomeUnknown || got.Receipt.Binding != recovery.Binding {
		t.Fatal("lost metadata response did not preserve unknown", err)
	}
	got, err = f.service.Recover(f.ctx, f.auth(tenant, "owner"), recovery)
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != recovery.Binding {
		t.Fatal("metadata recovery did not classify original commit", err)
	}
	assertMetadata(t, f, tenant, "Updated metadata", "updated", "2", 1)
}

// This policy seam changes a current action decision after preparation, not
// persistent membership or the session owner's native authorization epoch.
func TestOrganizationMetadataCurrentPolicy(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	policy := &metadataPolicy{}
	config := f.configuration
	config.Authorization = policy
	service, err := organizationpg.NewService(f.participant, config)
	if err != nil {
		t.Fatal(err)
	}
	p, err := service.PrepareUpdate(f.ctx, metadataRequest(t, f, tenant, "owner", 1), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	policy.denied = true
	if _, err = service.Execute(f.ctx, p); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("changed policy did not deny", err)
	}
	assertMetadata(t, f, tenant, "Example", "example", "1", 0)
}

type metadataPolicy struct{ denied bool }

func (p *metadataPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	outcome := authorization.Allow
	if p.denied && c.Request.Action == authorization.Action(organization.Update) && c.Request.Resource.Type == "organization" {
		outcome = authorization.Deny
	}
	return authorization.Decision{Outcome: outcome, Revision: c.PolicyRevision}, nil
}

func TestOrganizationMetadataRecoveryRequiresCurrentActionAndManagementRole(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "second", organization.RoleAdministrator, 1)
	policy := &metadataPolicy{}
	config := f.configuration
	config.Authorization = policy
	service, err := organizationpg.NewService(f.participant, config)
	if err != nil {
		t.Fatal(err)
	}
	p, err := service.PrepareUpdate(f.ctx, metadataRequest(t, f, tenant, "second", 2), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := service.Execute(f.ctx, p); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal(err)
	}
	recovery, err := p.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	policy.denied = true
	if _, err = service.Recover(f.ctx, f.auth(tenant, "second"), recovery); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("recovery bypassed current organization update policy", err)
	}
	policy.denied = false
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET role='member',version=version+1 WHERE tenant_id=$1 AND user_id='second'`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Recover(f.ctx, f.auth(tenant, "second"), recovery); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("demoted actor recovered management outcome", err)
	}
}

func TestOrganizationMetadataScopedAuthorityWithdrawal(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	p, err := f.service.PrepareUpdate(f.ctx, metadataRequest(t, f, tenant, "owner", 1), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), metadataOrganization, "owner")
	if err != nil {
		t.Fatal(err)
	}
	// The authorization owner can withdraw its own exact organization-scoped
	// evidence independently of the membership snapshot and global session.
	if _, err = authority.AdvanceAuthority(f.ctx, f.pool.Raw(), scope, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	got, err := f.service.Execute(f.ctx, p)
	if !errors.Is(err, organization.ErrForbidden) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("withdrawn scoped authorization permitted update", err, got.Receipt.Outcome)
	}
	assertMetadata(t, f, tenant, "Example", "example", "1", 0)
}

func TestOrganizationMetadataFieldAndTenantIsolation(t *testing.T) {
	f := newOrgFixture(t)
	f.create(t, "org-test-basic")
	f.create(t, "org-test-scope")
	r := metadataRequest(t, f, "org-test-basic", "owner", 1)
	r.Slug = "example"
	p, err := f.service.PrepareUpdate(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.service.Execute(f.ctx, p); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal(err)
	}
	assertMetadata(t, f, "org-test-basic", "Updated metadata", "example", "2", 1)
	r.CommandID, r.OrganizationVersion, r.Slug = commandID(t), 2, "shared-between-tenants"
	p, err = f.service.PrepareUpdate(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.service.Execute(f.ctx, p); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal(err)
	}
	assertMetadata(t, f, "org-test-basic", "Updated metadata", "shared-between-tenants", "3", 2)
	r = metadataRequest(t, f, "org-test-scope", "owner", 1)
	r.Name, r.Slug = "Example", "shared-between-tenants"
	p, err = f.service.PrepareUpdate(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.service.Execute(f.ctx, p); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("cross-tenant slug was reserved globally", err)
	}
	assertMetadata(t, f, "org-test-scope", "Example", "shared-between-tenants", "2", 1)
}

func TestOrganizationMetadataConcurrentVersionContention(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	var prepared [2]organizationpg.PreparedCommand
	for i := range prepared {
		r := metadataRequest(t, f, tenant, "owner", 1)
		r.Name, r.Slug = "Contender "+strconv.Itoa(i), "contender-"+strconv.Itoa(i)
		var err error
		prepared[i], err = f.service.PrepareUpdate(f.ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
	}
	type outcome struct {
		result organization.StoreResult
		err    error
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	for _, p := range prepared {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, err := f.service.Execute(f.ctx, p)
			results <- outcome{result, err}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	committed, conflicted := 0, 0
	for got := range results {
		if got.result.Receipt.Outcome == identity.CommitOutcomeCommitted && got.err == nil {
			committed++
		}
		if got.result.Receipt.Outcome == identity.CommitOutcomeNotCommitted && errors.Is(got.err, organization.ErrConflict) {
			conflicted++
		}
	}
	if committed != 1 || conflicted != 1 {
		t.Fatal("same-version contenders did not select exactly one winner", committed, conflicted)
	}
	view, err := f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, CorrelationID: "metadata-contention"})
	if err != nil || view.Organization.Version != 2 || !(view.Organization.Name == "Contender 0" && view.Organization.Slug == "contender-0" || view.Organization.Name == "Contender 1" && view.Organization.Slug == "contender-1") {
		t.Fatal("contention mixed metadata or lost version", err)
	}
}

func TestOrganizationMetadataNativeCommandValidation(t *testing.T) {
	f := newOrgFixture(t)
	f.create(t, "org-test-basic")
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	core, err := organization.NewService(f.sessions, repository, f.configuration.Authorization, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	c, err := core.PrepareUpdate(f.ctx, metadataRequest(t, f, "org-test-basic", "owner", 1))
	if err != nil {
		t.Fatal(err)
	}
	native, err := f.participant.MapCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := native.Feature()
	plan := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: f.participant.Descriptor(), Operation: organization.Update.Descriptor()}, SubjectType: "organization", Lifecycle: &kernel.LifecyclePlan{EventType: "organization.updated.v1", BeforeVersion: 1, AfterVersion: 2}, Audits: []kernel.AuditPlan{{EventType: "identity.organization.update", RetentionClass: "protected"}}, CommandCounters: &kernel.CommandCounterPlan{}}
	if err = f.participant.ValidateFeatureCommand(native, plan); err != nil {
		t.Fatal("valid native baseline rejected", err)
	}
	for _, entry := range []struct{ field, text string }{{"name", ""}, {"name", strings.Repeat("a", 257)}, {"name", "control\nname"}, {"slug", "UPPERCASE"}, {"slug", "-slug"}, {"actor-role", "member"}, {"role", "owner"}} {
		changed, _ := native.Feature()
		for i := range changed.Fields {
			if changed.Fields[i].Name == "organization."+entry.field {
				changed.Fields[i].Value.Text = entry.text
			}
		}
		bad, err := identity.NewFeatureSessionCommand(changed, f.auth("org-test-basic", "owner").Bearer)
		if err != nil {
			t.Fatal("malformed domain field did not reach native contributor", err)
		}
		if err = f.participant.ValidateFeatureCommand(bad, plan); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("independently callable native contributor accepted malformed update", entry.field, err)
		}
	}
	if spec.Operation != organization.Update.Descriptor() {
		t.Fatal("native baseline used wrong operation")
	}
}

func TestOrganizationMetadataRiskDenialAndReplayCharge(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	for attempt := 1; attempt <= 21; attempt++ {
		r := metadataRequest(t, f, tenant, "owner", uint64(attempt))
		r.Name, r.Slug = "Risk update "+strconv.Itoa(attempt), "risk-"+strconv.Itoa(attempt)
		p, err := f.service.PrepareUpdate(f.ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal("risk preparation failed before protected counter decision", err)
		}
		got, err := f.service.Execute(f.ctx, p)
		want := identity.CommitOutcomeCommitted
		if attempt == 21 {
			want = identity.CommitOutcomeNotCommitted
			if !errors.Is(err, organization.ErrForbidden) {
				t.Fatal("native privileged threshold did not deny", err)
			}
		} else if err != nil {
			t.Fatal("privileged allowance denied before configured threshold", attempt, err)
		}
		if got.Receipt.Outcome != want {
			t.Fatal("risk threshold returned wrong durable outcome", attempt, got.Receipt.Outcome)
		}
		again, err := f.service.Execute(f.ctx, p)
		if err != nil || again.Receipt.Outcome != want || again.Receipt.Binding != got.Receipt.Binding {
			t.Fatal("risk replay changed terminal command", attempt, err)
		}
		var charges int
		var minimum, maximum string
		if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization_risk.counter_charges WHERE tenant_id=$1 AND operation='identity.organization.update'),min(value)::text,max(value)::text FROM organization_risk.counter_windows WHERE tenant_id=$1 AND operation='identity.organization.update'`, tenant).Scan(&charges, &minimum, &maximum); err != nil || charges != attempt || minimum != strconv.Itoa(attempt) || maximum != strconv.Itoa(attempt) {
			t.Fatal("same-command replay duplicated protected risk charge", attempt, charges, minimum, maximum, err)
		}
	}
	assertMetadata(t, f, tenant, "Risk update 20", "risk-20", "21", 20)
}
