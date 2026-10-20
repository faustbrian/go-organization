//go:build integration

package postgres_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func dynamicRoleFixture(t *testing.T) *orgFixture {
	t.Helper()
	f := newOrgFixture(t, organizationpg.DynamicRoleMigrationSource{Version: 305})
	f.dynamicRoles = customRoleConfig()
	f.compose(t)
	return f
}
func dynamicRoleRequest(t *testing.T, f *orgFixture, epoch uint64) organization.DynamicRoleRequest {
	return organization.DynamicRoleRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: epoch, RoleID: "reader", Name: "Reader", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}}, CorrelationID: "roles"}
}
func roleBindingRequest(t *testing.T, f *orgFixture, epoch uint64) organization.RoleBindingRequest {
	return organization.RoleBindingRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: epoch, RoleID: "reader", RoleVersion: 1, UserID: "member", OrganizationMemberVersion: 1, CorrelationID: "roles"}
}
func commitRole(t *testing.T, f *orgFixture, p organizationpg.PreparedCommand, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.Execute(f.ctx, p); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("role commit", e)
	}
}
func prepareRole(t *testing.T, f *orgFixture, epoch uint64) organizationpg.PreparedCommand {
	t.Helper()
	p, e := f.service.PrepareCreateDynamicRole(f.ctx, dynamicRoleRequest(t, f, epoch), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestDynamicRoleNativeAuthority(t *testing.T) {
	f := dynamicRoleFixture(t)
	f.create(t, "org-test-basic")
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	p := prepareRole(t, f, 2)
	commitRole(t, f, p, nil)
	b := roleBindingRequest(t, f, 3)
	p, e := f.service.PrepareAssignDynamicRole(f.ctx, b, "127.0.0.1")
	commitRole(t, f, p, e)
	check := organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: metadataOrganization, OrganizationVersion: 4, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "roles"}
	if d, e := f.service.CheckPermission(f.ctx, check); e != nil || d.Outcome != authorization.Allow {
		t.Fatal("bound member permission", e)
	}
	// Config and command projections are copied, including native retained policy.
	f.dynamicRoles.Catalog[0].Action = "document.delete"
	f.configuration.Core.DynamicRoles.Catalog[0].Action = "document.delete"
	if d, e := f.service.CheckPermission(f.ctx, check); e != nil || d.Outcome != authorization.Allow {
		t.Fatal("caller catalog changed retained service", e)
	}
	r := dynamicRoleRequest(t, f, 4)
	r.Authentication = check.Authentication
	if _, e = f.service.PrepareCreateDynamicRole(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("custom permission conferred management", e)
	}
	q := organization.DynamicRoleReadRequest{Authentication: f.auth("org-test-scope", "owner"), OrganizationID: metadataOrganization, RoleID: "reader", CorrelationID: "scope"}
	if _, e = f.service.GetDynamicRole(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("cross-tenant role read", e)
	}
	other := dynamicRoleRequest(t, f, 4)
	other.OrganizationID = "other-org"
	if _, e = f.service.PrepareCreateDynamicRole(f.ctx, other, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("cross-org management", e)
	}
	r = dynamicRoleRequest(t, f, 4)
	r.Statements[0].PermissionID = "unregistered"
	if _, e = f.service.PrepareCreateDynamicRole(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrInvalidInput) {
		t.Fatal("unknown permission admitted", e)
	}
	r = dynamicRoleRequest(t, f, 4)
	r.RoleID = "another"
	p, e = f.service.PrepareCreateDynamicRole(f.ctx, r, "127.0.0.1")
	commitRole(t, f, p, e)
	r = dynamicRoleRequest(t, f, 5)
	r.RoleID = "over-limit"
	p, e = f.service.PrepareCreateDynamicRole(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("maximum roles bypassed", e)
	}
	// Unknown persisted statements cannot be silently ignored while another
	// known allow grants access. This is a storage-corruption/old-catalog seam.
	if _, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization.custom_roles SET statements='[{"PermissionID":"unregistered","ResourceID":"one","Effect":1}]' WHERE tenant_id='org-test-basic' AND role_id='reader'`); e != nil {
		t.Fatal(e)
	}
	check.OrganizationVersion = 5
	if _, e = f.service.CheckPermission(f.ctx, check); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("unknown stored statement did not fail closed", e)
	}
	if _, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization.custom_roles SET statements='[{"PermissionID":"document-read","ResourceID":"one","Effect":1}]' WHERE tenant_id='org-test-basic' AND role_id='reader'`); e != nil {
		t.Fatal(e)
	}
	remove, e := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 5, UserID: "member", MemberVersion: 1, CorrelationID: "roles"}, "127.0.0.1")
	commitRole(t, f, remove, e)
	check.OrganizationVersion = 6
	if _, e = f.service.CheckPermission(f.ctx, check); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("removed member retained custom role", e)
	}
	rereadmit, e := f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 6, UserID: "member", MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "roles"}, "127.0.0.1")
	commitRole(t, f, rereadmit, e)
	check.OrganizationVersion = 7
	if d, e := f.service.CheckPermission(f.ctx, check); e != nil || d.Outcome != authorization.Deny {
		t.Fatal("readmission revived stale role binding", e)
	}
}

func TestDynamicRoleAtomicRollbackAndRecovery(t *testing.T) {
	f := dynamicRoleFixture(t)
	f.create(t, "org-test-basic")
	p := prepareRole(t, f, 1)
	_, e := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.reject_role_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled role rollback'; END $$; CREATE TRIGGER reject_role_lifecycle BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION organization.reject_role_lifecycle()`)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("outbox failure retained role", e)
	}
	var count, epoch int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.custom_roles),version::integer FROM organization.organizations WHERE tenant_id='org-test-basic'`).Scan(&count, &epoch); e != nil || count != 0 || epoch != 1 {
		t.Fatal("role or epoch escaped rollback", e)
	}
	_, e = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_role_lifecycle ON public.identity_outbox_bindings; DROP FUNCTION organization.reject_role_lifecycle()`)
	if e != nil {
		t.Fatal(e)
	}
	lossy, fault := f.lostCommitService(t)
	p, e = lossy.PrepareCreateDynamicRole(f.ctx, dynamicRoleRequest(t, f, 1), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	recovery, e := p.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	fault.armed.Store(true)
	got, e := lossy.Execute(f.ctx, p)
	if e == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("lost role acknowledgement claimed outcome", e)
	}
	for range 2 {
		got, e = f.service.Recover(f.ctx, f.auth("org-test-basic", "owner"), recovery)
		if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != recovery.Binding {
			t.Fatal("role original recovery", e)
		}
	}
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.custom_roles),version::integer FROM organization.organizations WHERE tenant_id='org-test-basic'`).Scan(&count, &epoch); e != nil || count != 1 || epoch != 2 {
		t.Fatal("recovery replayed role", e)
	}
}

func TestDynamicRoleConcurrentPolicyFence(t *testing.T) {
	f := dynamicRoleFixture(t)
	f.create(t, "org-test-basic")
	p := prepareRole(t, f, 1)
	commitRole(t, f, p, nil)
	r := dynamicRoleRequest(t, f, 2)
	r.RoleVersion = 1
	r.Name = "First"
	a, e := f.service.PrepareUpdateDynamicRole(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	r.CommandID = commandID(t)
	r.Name = "Second"
	b, e := f.service.PrepareUpdateDynamicRole(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for _, p := range []organizationpg.PreparedCommand{a, b} {
		wg.Add(1)
		go func(p organizationpg.PreparedCommand) {
			defer wg.Done()
			got, e := f.service.Execute(f.ctx, p)
			results <- e == nil && got.Receipt.Outcome == identity.CommitOutcomeCommitted
		}(p)
	}
	wg.Wait()
	close(results)
	success := 0
	for ok := range results {
		if ok {
			success++
		}
	}
	if success != 1 {
		t.Fatal("stale concurrent policy update committed", success)
	}
	var epoch, version int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT o.version::integer,r.version::integer FROM organization.organizations o JOIN organization.custom_roles r USING(tenant_id,organization_id) WHERE o.tenant_id='org-test-basic'`).Scan(&epoch, &version); e != nil || epoch != 3 || version != 2 {
		t.Fatal("policy race epochs", e)
	}
}

func TestDynamicRoleFinalSessionFence(t *testing.T) {
	f := dynamicRoleFixture(t)
	f.create(t, "org-test-basic")
	p := prepareRole(t, f, 1)
	_, e := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.role_withdraw_session() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=NEW.tenant_id AND user_id='owner'; RETURN NEW; END $$; CREATE TRIGGER role_withdraw_session AFTER INSERT ON organization.custom_roles FOR EACH ROW EXECUTE FUNCTION organization.role_withdraw_session()`)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("session withdrawal committed role", e)
	}
	var count, epoch int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.custom_roles),version::integer FROM organization.organizations WHERE tenant_id='org-test-basic'`).Scan(&count, &epoch); e != nil || count != 0 || epoch != 1 {
		t.Fatal("final fence effects survived rollback", e)
	}
}

func TestDynamicRoleBindingAtomicRollback(t *testing.T) {
	f := dynamicRoleFixture(t)
	f.create(t, "org-test-basic")
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	p := prepareRole(t, f, 2)
	commitRole(t, f, p, nil)
	p, e := f.service.PrepareAssignDynamicRole(f.ctx, roleBindingRequest(t, f, 3), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.reject_binding_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled binding rollback'; END $$; CREATE TRIGGER reject_binding_lifecycle BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION organization.reject_binding_lifecycle()`)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("binding outbox failure retained mutation", e)
	}
	var count, epoch, memberAuthority int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.role_bindings),o.version::integer,m.authorization_version::integer FROM organization.organizations o JOIN organization.memberships m USING(tenant_id,organization_id) WHERE o.tenant_id='org-test-basic' AND m.user_id='member'`).Scan(&count, &epoch, &memberAuthority); e != nil || count != 0 || epoch != 3 || memberAuthority != 1 {
		t.Fatal("binding, epoch or target authority escaped rollback", e)
	}
}
