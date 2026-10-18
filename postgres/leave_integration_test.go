//go:build integration

package postgres_test

import (
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func nativeLeave(t *testing.T, f *orgFixture, tenant, actor string, version uint64) organization.LeaveRequest {
	t.Helper()
	return organization.LeaveRequest{Authentication: f.auth(tenant, actor), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: version, CorrelationID: "self-leave"}
}

func readmitAfterLeave(t *testing.T, f *orgFixture, tenant string, version uint64) {
	t.Helper()
	p, err := f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: version, UserID: "member", Role: organization.RoleMember, MemberVersion: 2, CorrelationID: "readmit"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, p)
}

func assertLeaveState(t *testing.T, f *orgFixture, tenant, actor, state, version string, count int) {
	t.Helper()
	var actual, epoch string
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT m.state,o.version::text,(SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.member.leave') FROM organization.memberships m JOIN organization.organizations o USING(tenant_id,organization_id) WHERE m.tenant_id=$1 AND m.organization_id=$2 AND m.user_id=$3`, tenant, string(metadataOrganization), actor).Scan(&actual, &epoch, &effects); err != nil || actual != state || epoch != version || effects != count {
		t.Fatal("leave state/organization epoch/effect count mismatch", err, actual, epoch, effects)
	}
}

func TestOrganizationSelfLeave(t *testing.T) {
	f := newOrgFixture(t)
	t.Run("self_tombstone_scope_session_replay_and_readmission", func(t *testing.T) {
		tenant := "org-test-basic"
		f.create(t, tenant)
		f.add(t, tenant, "member", organization.RoleMember, 1)
		assertLeaveRejectsForgedTarget(t, f, tenant)
		prepared, err := f.service.PrepareLeaveMember(f.ctx, nativeLeave(t, f, tenant, "member", 2), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		handle, err := prepared.Recovery()
		if err != nil {
			t.Fatal(err)
		}
		if handle.Binding.ActorID != "member" || handle.Binding.UserID != "member" || handle.Binding.OperationID != string(organization.LeaveMember) {
			t.Fatal("leave binding is not self-only")
		}
		committedTeam(t, f, prepared)
		assertLeaveState(t, f, tenant, "member", "removed", "3", 1)
		if _, err = f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "member"), OrganizationID: metadataOrganization, CorrelationID: "left"}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("left member read organization", err)
		}
		if _, err = f.service.Recover(f.ctx, f.auth(tenant, "member"), handle); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("retained receipt replaced current membership", err)
		}
		// Leave advances only the organization-scoped membership authority, not
		// identity/password/session. The same session may create another org.
		other, err := f.service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: f.auth(tenant, "member"), CommandID: commandID(t), ID: "independent", Slug: "independent", Name: "Independent", CorrelationID: "left"}, "127.0.0.1")
		if err != nil {
			t.Fatal("leave revoked global/session authority", err)
		}
		committedTeam(t, f, other)
		readmitAfterLeave(t, f, tenant, 3)
		retained, err := f.service.Recover(f.ctx, f.auth(tenant, "member"), handle)
		if err != nil || retained.Receipt.Outcome != identity.CommitOutcomeCommitted || retained.Receipt.Binding != handle.Binding {
			t.Fatal("legitimate readmission did not permit exact historical metadata", err)
		}
		committedTeam(t, f, prepared)
		assertLeaveState(t, f, tenant, "member", "active", "4", 1)
		var version, epoch string
		if err = f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,authorization_version::text FROM organization.memberships WHERE tenant_id=$1 AND user_id='member' AND organization_id=$2`, tenant, string(metadataOrganization)).Scan(&version, &epoch); err != nil || version != "3" || epoch != "3" {
			t.Fatal("readmission failed exact tombstone epochs", err)
		}
		var audits, events int
		commandBytes, err := base64.RawURLEncoding.DecodeString(string(handle.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.action='identity.organization.remove_member'),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$1 AND m.topic='membership.removed.v1')`, commandBytes).Scan(&audits, &events); err != nil || audits != 1 || events != 1 {
			t.Fatal("leave lacks canonical removal audit/outbox", err)
		}
	})
	t.Run("last_owner_foreign_nonmember_and_stale_deny", func(t *testing.T) {
		tenant := "org-test-scope"
		f.create(t, tenant)
		if _, err := f.service.PrepareLeaveMember(f.ctx, nativeLeave(t, f, tenant, "owner", 1), "127.0.0.1"); !errors.Is(err, organization.ErrLastOwner) {
			t.Fatal("last recovery owner left", err)
		}
		if _, err := f.service.PrepareLeaveMember(f.ctx, nativeLeave(t, f, tenant, "outsider", 1), "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("nonmember leave admitted", err)
		}
		f.add(t, tenant, "member", organization.RoleMember, 1)
		r := nativeLeave(t, f, tenant, "member", 1)
		if _, err := f.service.PrepareLeaveMember(f.ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("stale leave admitted", err)
		}
		r.OrganizationVersion = 2
		r.Authentication.TenantID = "org-test-basic"
		if _, err := f.service.PrepareLeaveMember(f.ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("foreign bearer leave admitted", err)
		}
		assertLeaveState(t, f, tenant, "member", "active", "2", 0)
	})
	t.Run("concurrent_owner_leave_and_remove_conserves_owner", func(t *testing.T) {
		tenant := "org-test-race"
		f.create(t, tenant)
		f.add(t, tenant, "second", organization.RoleOwner, 1)
		leave, err := f.service.PrepareLeaveMember(f.ctx, nativeLeave(t, f, tenant, "owner", 2), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		remove, err := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "second"), CommandID: commandID(t), OrganizationID: metadataOrganization, UserID: "second", OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "owner-race"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		results := make(chan organization.StoreResult, 2)
		for _, p := range []organizationpg.PreparedCommand{leave, remove} {
			wg.Go(func() { result, _ := f.service.Execute(f.ctx, p); results <- result })
		}
		wg.Wait()
		close(results)
		wins := 0
		for result := range results {
			if result.Receipt.Outcome == identity.CommitOutcomeCommitted {
				wins++
			}
		}
		var owners, members int
		if err = f.pool.Raw().QueryRow(f.ctx, `SELECT owner_count,member_count FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&owners, &members); err != nil || wins != 1 || owners != 1 || members != 1 {
			t.Fatal("racing self-removals lost last owner", err, wins, owners, members)
		}
	})
	t.Run("late_session_and_membership_withdrawal", func(t *testing.T) {
		for _, tenant := range []string{"org-test-target", "org-test-unknown", "org-test-rollback"} {
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			p, err := f.service.PrepareLeaveMember(f.ctx, nativeLeave(t, f, tenant, "member", 2), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			if tenant == "org-test-target" {
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='member'`, tenant)
			} else if tenant == "org-test-rollback" {
				scope, e := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), metadataOrganization, "member")
				if e != nil {
					t.Fatal(e)
				}
				_, err = authority.AdvanceAuthority(f.ctx, f.pool.Raw(), scope, 1, time.Second)
			} else {
				remove, e := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, UserID: "member", OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "withdraw"}, "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				committedTeam(t, f, remove)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := f.service.Execute(f.ctx, p); err == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("withdrawn authority committed leave", err)
			}
		}
	})
}

func TestOrganizationSelfLeaveAtomicFailures(t *testing.T) {
	for _, boundary := range []string{"audit", "outbox"} {
		t.Run(boundary, func(t *testing.T) {
			f := newOrgFixture(t)
			tenant := "org-test-rollback"
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			p, err := f.service.PrepareLeaveMember(f.ctx, nativeLeave(t, f, tenant, "member", 2), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			table := "audit.records"
			body := `IF NEW.outcome=1 AND NEW.action='identity.organization.remove_member' THEN RAISE EXCEPTION 'synthetic leave failure'; END IF; RETURN NEW;`
			if boundary == "outbox" {
				table = "public.identity_outbox_bindings"
				body = `RAISE EXCEPTION 'synthetic leave failure';`
			}
			// Fail protected success publication, not the coordinator's separate
			// aborted-result audit. Keep the original owner journal available.
			_, err = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.leave_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+body+` END $$; CREATE TRIGGER leave_fail BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION public.leave_fail()`)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.service.Execute(f.ctx, p)
			if err == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("failed required effect did not abort leave", err)
			}
			assertLeaveState(t, f, tenant, "member", "active", "2", 0)
			var epoch string
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT authorization_version::text FROM organization.memberships WHERE tenant_id=$1 AND user_id='member'`, tenant).Scan(&epoch); err != nil || epoch != "1" {
				t.Fatal("rollback advanced member authority", err)
			}
			if _, err = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER leave_fail ON `+table+`; DROP FUNCTION public.leave_fail()`); err != nil {
				t.Fatal(err)
			}
			handle, err := p.Recovery()
			if err != nil {
				t.Fatal(err)
			}
			got, err = f.service.Recover(f.ctx, f.auth(tenant, "member"), handle)
			var unavailable identity.UnavailableError
			if !errors.As(err, &unavailable) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted || got.Receipt.Binding != handle.Binding {
				t.Fatal("rollback recovery did not preserve original not-committed result", err)
			}
		})
	}
}

func TestOrganizationSelfLeaveLostAcknowledgement(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-unknown"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	s, fault := f.lostCommitService(t)
	p, err := s.PrepareLeaveMember(f.ctx, nativeLeave(t, f, tenant, "member", 2), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handle, err := p.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	fault.armed.Store(true)
	got, err := s.Execute(f.ctx, p)
	if err == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown || got.Receipt.Binding != handle.Binding {
		t.Fatal("lost response did not preserve original unknown", err)
	}
	assertLeaveState(t, f, tenant, "member", "removed", "3", 1)
	if _, err = f.service.Recover(f.ctx, f.auth(tenant, "member"), handle); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("unknown outcome bypassed current disclosure policy", err)
	}
	readmitAfterLeave(t, f, tenant, 3)
	got, err = f.service.Recover(f.ctx, f.auth(tenant, "member"), handle)
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
		t.Fatal("exact recovery after legitimate readmission failed", err)
	}
	assertLeaveState(t, f, tenant, "member", "active", "4", 1)
}

func TestOrganizationSelfLeaveDoesNotReviveTeamBindings(t *testing.T) {
	f := teamFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	add, err := f.service.PrepareAddTeamMember(f.ctx, teamAddRequest(t, f, tenant, 3), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, add)
	q := organization.TeamReadRequest{Authentication: f.auth(tenant, "member"), OrganizationID: metadataOrganization, TeamID: "engineering", Limit: 10, CorrelationID: "self-leave"}
	if got, err := f.service.ListTeamMembers(f.ctx, q); err != nil || len(got.TeamMembers) != 1 {
		t.Fatal("actual team binding missing before leave", err)
	}
	p, err := f.service.PrepareLeaveMember(f.ctx, nativeLeave(t, f, tenant, "member", 4), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, p)
	if _, err = f.service.ListTeamMembers(f.ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("left member retained team access", err)
	}
	readmitAfterLeave(t, f, tenant, 5)
	if _, err = f.service.ListTeamMembers(f.ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("readmission revived old team binding", err)
	}
	q.TeamID = ""
	if got, err := f.service.ListMyTeams(f.ctx, q); err != nil || len(got.Teams) != 0 {
		t.Fatal("readmission returned stale mine binding", err)
	}
}

func TestOrganizationSelfLeaveRacesOwnerTransfer(t *testing.T) {
	f := newOwnerFixture(t)
	tenant := transferTenants["org-test-basic"]
	f.create(t, tenant)
	f.add(t, tenant, "second", organization.RoleOwner, 1)
	f.add(t, tenant, "member", organization.RoleMember, 2)
	leave, err := f.service.PrepareLeaveMember(f.ctx, nativeLeave(t, f.orgFixture, tenant, transferUser("second"), 3), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	transfer, err := f.service.PrepareOwnerTransfer(f.ctx, nativeTransfer(t, f, tenant, "owner", "member", 3, 1, 1), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan organization.StoreResult, 2)
	for _, p := range []organizationpg.PreparedCommand{leave, transfer} {
		wg.Go(func() { r, _ := f.service.Execute(f.ctx, p); results <- r })
	}
	wg.Wait()
	close(results)
	wins := 0
	for r := range results {
		if r.Receipt.Outcome == identity.CommitOutcomeCommitted {
			wins++
		}
	}
	var owners, actual int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT owner_count,(SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND state='active' AND role='owner') FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&owners, &actual); err != nil || wins != 1 || owners < 1 || owners != actual {
		t.Fatal("transfer/leave lost conserved recovery owner", err, wins, owners, actual)
	}
}

func assertLeaveRejectsForgedTarget(t *testing.T, f *orgFixture, tenant string) {
	t.Helper()
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	core, err := organization.NewService(f.sessions, repository, fixturePolicy{}, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	c, err := core.PrepareLeaveMember(f.ctx, nativeLeave(t, f, tenant, "member", 2))
	if err != nil {
		t.Fatal(err)
	}
	native, err := f.participant.MapCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := native.Feature()
	plan := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: f.participant.Descriptor(), Operation: spec.Operation}, SubjectType: "organization", Lifecycle: &kernel.LifecyclePlan{EventType: "membership.removed.v1", BeforeVersion: 2, AfterVersion: 3}, Audits: []kernel.AuditPlan{{EventType: "identity.organization.remove_member", RetentionClass: "protected"}}, CommandCounters: &kernel.CommandCounterPlan{}}
	if err = f.participant.ValidateFeatureCommand(native, plan); err != nil {
		t.Fatal("valid native self leave rejected", err)
	}
	spec.Binding.UserID = "outsider"
	forged, err := identity.NewFeatureSessionCommand(spec, f.auth(tenant, "member").Bearer)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.participant.ValidateFeatureCommand(forged, plan); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("public contributor accepted arbitrary leave target", err)
	}
}

func TestOrganizationSelfLeaveRecoveryCurrentAuthority(t *testing.T) {
	f := newOrgFixture(t)
	for i, variant := range []struct{ stage, withdrawal string }{{"get", "session"}, {"get", "epoch"}, {"query", "member"}, {"query", "epoch"}} {
		t.Run(variant.stage+"/"+variant.withdrawal, func(t *testing.T) {
			tenant := []string{"org-test-basic", "org-test-scope", "org-test-race", "org-test-target"}[i]
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			p, err := f.service.PrepareLeaveMember(f.ctx, nativeLeave(t, f, tenant, "member", 2), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			committedTeam(t, f, p)
			readmitAfterLeave(t, f, tenant, 3)
			handle, err := p.Recovery()
			if err != nil {
				t.Fatal(err)
			}
			policy := &recoveryWithdrawalPolicy{fixture: f, operation: organization.LeaveMember, stage: variant.stage, withdrawal: variant.withdrawal, tenant: tenant, user: "member"}
			config := f.configuration
			config.Authorization = policy
			config.Coordinator, err = kernel.NewCoordinator(f.pool, config.Registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x45}}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 1}})
			if err != nil {
				t.Fatal(err)
			}
			s, err := organizationpg.NewService(f.participant, config)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Recover(f.ctx, f.auth(tenant, "member"), handle)
			if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("current readmitted member recovery denied", err)
			}
			policy.armed = true
			got, err = s.Recover(f.ctx, f.auth(tenant, "member"), handle)
			if !policy.fired || !errors.Is(err, organization.ErrForbidden) || got != (organization.StoreResult{}) {
				t.Fatal("postcallback withdrawal disclosed leave metadata", err)
			}
		})
	}
}
