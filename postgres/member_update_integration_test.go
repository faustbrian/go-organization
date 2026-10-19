//go:build integration

package postgres_test

import (
	"errors"
	"strconv"
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

func roleRequest(t *testing.T, f *orgFixture, tenant, actor, target string, epoch, version uint64, role organization.Role) organization.MemberRequest {
	t.Helper()
	return organization.MemberRequest{Authentication: f.auth(tenant, actor), CommandID: commandID(t), OrganizationID: metadataOrganization, UserID: identity.UserID(target), OrganizationVersion: epoch, MemberVersion: version, Role: role, CorrelationID: "member-role"}
}

func assertRole(t *testing.T, f *orgFixture, tenant, user string, epoch, version, authVersion uint64, role organization.Role, owners, members, effects int) {
	t.Helper()
	var actualEpoch, actualVersion, actualAuth string
	var actualRole, state string
	var actualOwners, actualMembers, actualEffects int
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT o.version::text,m.version::text,m.authorization_version::text,m.role,m.state,o.owner_count,o.member_count,(SELECT count(*) FROM organization.command_effects e WHERE e.tenant_id=$1 AND e.operation='identity.organization.member.update') FROM organization.organizations o JOIN organization.memberships m USING(tenant_id,organization_id) WHERE o.tenant_id=$1 AND o.organization_id=$2 AND m.user_id=$3`, tenant, string(metadataOrganization), user).Scan(&actualEpoch, &actualVersion, &actualAuth, &actualRole, &state, &actualOwners, &actualMembers, &actualEffects)
	if err != nil || actualEpoch != strconv.FormatUint(epoch, 10) || actualVersion != strconv.FormatUint(version, 10) || actualAuth != strconv.FormatUint(authVersion, 10) || actualRole != string(role) || state != "active" || actualOwners != owners || actualMembers != members || actualEffects != effects {
		t.Fatal("role/version/scoped authority/counts/effects not atomic", err, actualEpoch, actualVersion, actualAuth, actualRole, actualOwners, actualMembers, actualEffects)
	}
	scope, err := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), metadataOrganization, identity.UserID(user))
	if err != nil {
		t.Fatal(err)
	}
	store, err := authority.NewAuthorityStore(f.pool.Raw(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.Get(f.ctx, scope)
	if err != nil || current.Version != authVersion {
		t.Fatal("membership and actual scoped authority diverged", err)
	}
}

func TestMemberRoleUpdateNativeContract(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "second", organization.RoleMember, 1)
	r := roleRequest(t, f, tenant, "owner", "second", 2, 1, organization.RoleAdministrator)
	p, err := f.service.PrepareUpdateMember(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handle, err := p.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := f.service.Execute(f.ctx, p)
		if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.BeforeVersion != 2 || got.Receipt.Feature.AfterVersion != 3 {
			t.Fatal("role update/replay failed", err)
		}
	}
	assertRole(t, f, tenant, "second", 3, 2, 2, organization.RoleAdministrator, 1, 2, 1)
	// New authority is executable, not just a row string: the promoted member
	// can perform current administrator actions using its unchanged real owner session.
	view, err := f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "second"), OrganizationID: metadataOrganization, CorrelationID: "role-read"})
	if err != nil || view.Actor.Role != organization.RoleAdministrator || view.Actor.Version != 2 || view.Actor.AuthorizationVersion != 2 {
		t.Fatal("current actor read omitted new role", err)
	}
	for _, request := range []organization.MemberRequest{
		roleRequest(t, f, tenant, "second", "second", 3, 2, organization.RoleOwner),
		roleRequest(t, f, tenant, "second", "owner", 3, 1, organization.RoleMember),
	} {
		if _, err := f.service.PrepareUpdateMember(f.ctx, request, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("administrator escalated owner authority", err)
		}
	}
	if _, err := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "owner", "owner", 3, 1, organization.RoleAdministrator), "127.0.0.1"); !errors.Is(err, organization.ErrLastOwner) {
		t.Fatal("last recovery owner demoted", err)
	}
	self, err := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "second", "second", 3, 2, organization.RoleMember), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	selfHandle, err := self.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, self)
	committedTeam(t, f, self) // historical replay after legitimate self-demotion
	got, err := f.service.Recover(f.ctx, f.auth(tenant, "second"), selfHandle)
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("self-demotion metadata recovery required renewed manager privilege", err)
	}
	assertRole(t, f, tenant, "second", 4, 3, 3, organization.RoleMember, 1, 2, 2)
	if _, err := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "second", "second", 4, 3, organization.RoleAdministrator), "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("demoted member retained management permission", err)
	}
	got, err = f.service.Recover(f.ctx, f.auth(tenant, "owner"), handle)
	if err != nil || got.Receipt.Binding != handle.Binding || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("role metadata recovery relabeled original result", err)
	}
	grant, err := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "owner", "second", 4, 3, organization.RoleOwner), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, grant)
	assertRole(t, f, tenant, "second", 5, 4, 4, organization.RoleOwner, 2, 2, 3)
	demote, err := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "owner", "owner", 5, 1, organization.RoleAdministrator), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, demote)
	assertRole(t, f, tenant, "owner", 6, 2, 2, organization.RoleAdministrator, 1, 2, 4)
	var events, audits int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND m.topic='membership.role_changed.v1'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND r.action='identity.organization.change_member_role' AND convert_from(r.canonical_record,'UTF8')::jsonb #>> '{attributes,retention.class}'='protected')`, tenant).Scan(&events, &audits)
	if err != nil || events != 4 || audits != 4 {
		t.Fatal("canonical protected role audit/lifecycle missing or duplicated", err, events, audits)
	}
}

func TestMemberRoleUpdateRollbackAndUnknownCommit(t *testing.T) {
	f := newOrgFixture(t)
	for i, table := range []string{"audit.records", "public.identity_outbox_bindings"} {
		tenant := []string{"org-test-basic", "org-test-rollback"}[i]
		f.create(t, tenant)
		f.add(t, tenant, "second", organization.RoleMember, 1)
		p, err := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "owner", "second", 2, 1, organization.RoleAdministrator), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		condition := "true"
		if i == 0 {
			condition = "NEW.action='identity.organization.change_member_role' AND NEW.outcome=1"
		}
		if _, err = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.role_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic role effect failure'; END $$; CREATE TRIGGER role_fail BEFORE INSERT ON `+table+` FOR EACH ROW WHEN (`+condition+`) EXECUTE FUNCTION public.role_fail()`); err != nil {
			t.Fatal(err)
		}
		got, err := f.service.Execute(f.ctx, p)
		if err == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("failed required role effect committed", err, got.Receipt.Outcome)
		}
		if _, err = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER role_fail ON `+table+`; DROP FUNCTION public.role_fail()`); err != nil {
			t.Fatal(err)
		}
		assertRole(t, f, tenant, "second", 2, 1, 1, organization.RoleMember, 1, 2, 0)
		got, err = f.service.Execute(f.ctx, p)
		if got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("failed role retry mutated instead of replaying", err)
		}
	}
	tenant := "org-test-unknown"
	f.create(t, tenant)
	f.add(t, tenant, "second", organization.RoleMember, 1)
	service, fault := f.lostCommitService(t)
	p, err := service.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "owner", "second", 2, 1, organization.RoleAdministrator), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handle, err := p.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	fault.armed.Store(true)
	got, err := service.Execute(f.ctx, p)
	if !fault.lost.Load() || err == nil || got.Receipt.Outcome != identity.CommitOutcomeUnknown || got.Receipt.Binding != handle.Binding {
		t.Fatal("lost role commit response not unknown", err)
	}
	got, err = f.service.Recover(f.ctx, f.auth(tenant, "owner"), handle)
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
		t.Fatal("code-free original role recovery failed", err)
	}
	assertRole(t, f, tenant, "second", 3, 2, 2, organization.RoleAdministrator, 1, 2, 1)
}

func TestMemberRoleUpdateCurrentAuthority(t *testing.T) {
	for _, withdrawal := range []string{"session", "actor-role", "actor-scope", "target-scope", "target-membership", "target-user", "tenant"} {
		t.Run(withdrawal, func(t *testing.T) {
			f := newOrgFixture(t)
			tenant := "org-test-basic"
			f.create(t, tenant)
			f.add(t, tenant, "second", organization.RoleAdministrator, 1)
			f.add(t, tenant, "member", organization.RoleMember, 2)
			r := roleRequest(t, f, tenant, "second", "member", 3, 1, organization.RoleAdministrator)
			p, err := f.service.PrepareUpdateMember(f.ctx, r, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			switch withdrawal {
			case "session":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='second'`, tenant)
			case "actor-role":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET role='member',version=version+1 WHERE tenant_id=$1 AND user_id='second'`, tenant)
			case "actor-scope", "target-scope":
				user := identity.UserID("second")
				if withdrawal == "target-scope" {
					user = "member"
				}
				scope, e := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), metadataOrganization, user)
				if e != nil {
					t.Fatal(e)
				}
				_, err = authority.AdvanceAuthority(f.ctx, f.pool.Raw(), scope, 1, time.Second)
			case "target-membership":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET version=version+1 WHERE tenant_id=$1 AND user_id='member'`, tenant)
			case "target-user":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id='member'`, tenant)
			case "tenant":
				r.Authentication.TenantID = "org-test-scope"
				if _, err := f.service.PrepareUpdateMember(f.ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
					t.Fatal("foreign tenant bearer admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.service.Execute(f.ctx, p)
			if err == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("withdrawn authority updated member role", err, got.Receipt.Outcome)
			}
			var effects, epoch int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::integer,(SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.member.update') FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&epoch, &effects); err != nil || epoch != 3 || effects != 0 {
				t.Fatal("authority denial retained role effect", err)
			}
		})
	}
}

func TestMemberRoleUpdateRecoveryAndReplayRevalidateAuthority(t *testing.T) {
	for _, stage := range []string{"get", "management", "query", "replay"} {
		t.Run(stage, func(t *testing.T) {
			f := newOrgFixture(t)
			tenant := "org-test-basic"
			f.create(t, tenant)
			f.add(t, tenant, "second", organization.RoleAdministrator, 1)
			f.add(t, tenant, "member", organization.RoleMember, 2)
			policy := &recoveryWithdrawalPolicy{fixture: f, operation: organization.UpdateMember, stage: stage, withdrawal: "role"}
			if stage == "replay" {
				policy.stage = "management"
			}
			config := f.configuration
			config.Authorization = policy
			var err error
			config.Coordinator, err = kernel.NewCoordinator(f.pool, config.Registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x45}}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 1}})
			if err != nil {
				t.Fatal(err)
			}
			s, err := organizationpg.NewService(f.participant, config)
			if err != nil {
				t.Fatal(err)
			}
			p, err := s.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "second", "member", 3, 1, organization.RoleAdministrator), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Execute(f.ctx, p)
			if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal(err)
			}
			handle, err := p.Recovery()
			if err != nil {
				t.Fatal(err)
			}
			policy.armed = true
			if stage == "replay" {
				got, err = s.Execute(f.ctx, p)
			} else {
				got, err = s.Recover(f.ctx, f.auth(tenant, "second"), handle)
			}
			if !policy.fired || !errors.Is(err, organization.ErrForbidden) || got != (organization.StoreResult{}) {
				t.Fatal("late withdrawn manager disclosed role outcome", err, got.Receipt.Outcome)
			}
		})
	}
}

func TestMemberRoleUpdateNativeValidation(t *testing.T) {
	f := newOrgFixture(t)
	f.create(t, "org-test-basic")
	f.add(t, "org-test-basic", "second", organization.RoleMember, 1)
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	core, err := organization.NewService(f.sessions, repository, f.configuration.Authorization, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	c, err := core.PrepareUpdateMember(f.ctx, roleRequest(t, f, "org-test-basic", "owner", "second", 2, 1, organization.RoleAdministrator))
	if err != nil {
		t.Fatal(err)
	}
	native, err := f.participant.MapCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	plan := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: f.participant.Descriptor(), Operation: organization.UpdateMember.Descriptor()}, SubjectType: "organization", Lifecycle: &kernel.LifecyclePlan{EventType: "membership.role_changed.v1", BeforeVersion: 2, AfterVersion: 3}, Audits: []kernel.AuditPlan{{EventType: "identity.organization.change_member_role", RetentionClass: "protected"}}, CommandCounters: &kernel.CommandCounterPlan{}}
	if err = f.participant.ValidateFeatureCommand(native, plan); err != nil {
		t.Fatal(err)
	}
	for _, fields := range []map[string]string{{"role": "custom-admin"}, {"role": "member"}, {"actor-role": "member"}, {"actor-role": "administrator", "role": "owner"}, {"actor-role": "administrator", "member-role": "owner"}} {
		spec, _ := native.Feature()
		for i := range spec.Fields {
			for name, value := range fields {
				if spec.Fields[i].Name == "organization."+name {
					spec.Fields[i].Value.Text = value
				}
			}
		}
		changed, err := identity.NewFeatureSessionCommand(spec, f.auth("org-test-basic", "owner").Bearer)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.participant.ValidateFeatureCommand(changed, plan); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("native caller bypassed static role restrictions", err)
		}
	}
	// The native mapped intent includes Role while every other original input
	// (including the session observation) stays frozen. It is not a fresh Prepare.
	spec, _ := native.Feature()
	for i := range spec.Fields {
		if spec.Fields[i].Name == "organization.role" {
			spec.Fields[i].Value.Text = "owner"
		}
	}
	changed, err := identity.NewFeatureSessionCommand(spec, f.auth("org-test-basic", "owner").Bearer)
	if err != nil || f.participant.ValidateFeatureCommand(changed, plan) != nil {
		t.Fatal("owner role grant mapping invalid", err)
	}
}

func TestMemberRoleUpdateContention(t *testing.T) {
	for _, competitor := range []string{"role", "remove", "owner-demotion"} {
		t.Run(competitor, func(t *testing.T) {
			f := newOrgFixture(t)
			tenant := "org-test-basic"
			f.create(t, tenant)
			targetRole := organization.RoleMember
			if competitor == "owner-demotion" {
				targetRole = organization.RoleOwner
			}
			f.add(t, tenant, "second", targetRole, 1)
			first, err := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "owner", "second", 2, 1, organization.RoleAdministrator), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			var second organizationpg.PreparedCommand
			switch competitor {
			case "role":
				second, err = f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "owner", "second", 2, 1, organization.RoleOwner), "127.0.0.1")
			case "remove":
				r := roleRequest(t, f, tenant, "owner", "second", 2, 1, "")
				second, err = f.service.PrepareRemoveMember(f.ctx, r, "127.0.0.1")
			case "owner-demotion":
				second, err = f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, tenant, "second", "owner", 2, 1, organization.RoleMember), "127.0.0.1")
			}
			if err != nil {
				t.Fatal(err)
			}
			type outcome struct {
				result organization.StoreResult
				err    error
			}
			results := make(chan outcome, 2)
			start := make(chan struct{})
			var group sync.WaitGroup
			for _, p := range []organizationpg.PreparedCommand{first, second} {
				group.Add(1)
				go func() {
					defer group.Done()
					<-start
					got, err := f.service.Execute(f.ctx, p)
					results <- outcome{got, err}
				}()
			}
			close(start)
			group.Wait()
			close(results)
			committed, denied := 0, 0
			for got := range results {
				if got.err == nil && got.result.Receipt.Outcome == identity.CommitOutcomeCommitted {
					committed++
				} else if got.err != nil && got.result.Receipt.Outcome == identity.CommitOutcomeNotCommitted {
					denied++
				} else {
					t.Fatal("role contention ambiguous", got.err, got.result.Receipt.Outcome)
				}
			}
			if committed != 1 || denied != 1 {
				t.Fatal("role contention did not select one winner", committed, denied)
			}
			var owners, members, activeOwners, epoch int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT owner_count,member_count,version::integer,(SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND state='active' AND role='owner') FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&owners, &members, &epoch, &activeOwners); err != nil || owners < 1 || owners != activeOwners || epoch != 3 || members < owners {
				t.Fatal("race lost recovery owner/counts", err)
			}
		})
	}
}

func TestMemberRoleUpdateOwnerTransferContention(t *testing.T) {
	f := newOwnerFixture(t)
	tenant := transferTenants["org-test-race"]
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	role, err := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f.orgFixture, tenant, "owner", transferUser("member"), 2, 1, organization.RoleAdministrator), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	transfer, err := f.service.PrepareOwnerTransfer(f.ctx, nativeTransfer(t, f, tenant, "owner", "member", 2, 1, 1), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result organization.StoreResult
		err    error
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	for _, p := range []organizationpg.PreparedCommand{role, transfer} {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			got, err := f.service.Execute(f.ctx, p)
			results <- outcome{got, err}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	committed, denied := 0, 0
	for got := range results {
		if got.err == nil && got.result.Receipt.Outcome == identity.CommitOutcomeCommitted {
			committed++
		} else if got.err != nil && got.result.Receipt.Outcome == identity.CommitOutcomeNotCommitted {
			denied++
		} else {
			t.Fatal("role/transfer contention ambiguous", got.err, got.result.Receipt.Outcome)
		}
	}
	if committed != 1 || denied != 1 {
		t.Fatal("role/transfer did not serialize exact epoch", committed, denied)
	}
	var owners, members, activeOwners, epoch int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT owner_count,member_count,version::integer,(SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND state='active' AND role='owner') FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&owners, &members, &epoch, &activeOwners); err != nil || owners != 1 || activeOwners != 1 || members != 2 || epoch != 3 {
		t.Fatal("role/transfer lost sole recovery owner", err)
	}
}
