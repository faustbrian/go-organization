//go:build integration

package consumer_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func customRoleConfig() organization.DynamicRoleConfig {
	return organization.DynamicRoleConfig{Version: 1, MaximumRoles: 2, Catalog: []organization.Permission{{ID: "document-read", Action: "document.read", ResourceType: "document"}, {ID: "document-write", Action: "document.write", ResourceType: "document"}}}
}

func TestOrganizationGenuineDynamicRoleConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "dynamic-role")
}

// This is invoked only after real signup -> verification -> password signin;
// every credential comes from the existing public consumer, not synthetic rows.
func exerciseGenuineDynamicRoles(t *testing.T, ctx context.Context, db *sql.DB, s *organizationpg.Service, owner, member, recoveryOwner organization.Authentication, memberID identity.UserID, fresh func() *organizationpg.Service) {
	t.Helper()
	source := organizationpg.DynamicRoleMigrationSource{Version: 7010}
	steps, e := source.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	backend, e := migrationpg.New(db)
	if e != nil {
		t.Fatal(e)
	}
	backend, e = backend.ForNamespace("organization")
	if e != nil {
		t.Fatal(e)
	}
	var history migrationList
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}} {
		more, e := source.Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		history = append(history, more...)
	}
	history = append(history, steps...)
	runner, e := migrations.NewRunner(history, backend)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = runner.Up(ctx); e != nil {
		t.Fatal("populated role migration", e)
	}
	if _, e = runner.Up(ctx); e != nil {
		t.Fatal("role migration replay", e)
	}
	id, e := identity.NewSubjectID()
	if e != nil {
		t.Fatal(e)
	}
	org := organization.ID(id)
	id, e = identity.NewSubjectID()
	if e != nil {
		t.Fatal(e)
	}
	role := organization.ID(id)
	commit := func(p organizationpg.PreparedCommand, e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
		if got, e := s.Execute(ctx, p); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine role mutation", e)
		}
	}
	commit(s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Genuine role consumer", Slug: "genuine-roles", CorrelationID: "roles"}, "127.0.0.1"))
	orgView, e := s.Get(ctx, organization.ReadRequest{Authentication: owner, OrganizationID: org, CorrelationID: "roles"})
	if e != nil {
		t.Fatal(e)
	}
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: orgView.Organization.Version, UserID: memberID, Role: organization.RoleMember, CorrelationID: "roles"}, "127.0.0.1"))
	orgView, e = s.Get(ctx, organization.ReadRequest{Authentication: owner, OrganizationID: org, CorrelationID: "roles"})
	if e != nil {
		t.Fatal(e)
	}
	r := organization.DynamicRoleRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, RoleID: role, OrganizationVersion: orgView.Organization.Version, Name: "Document reader", CorrelationID: "roles", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "document-one", Effect: authorization.Allow}}}
	created, e := s.PrepareCreateDynamicRole(ctx, r, "127.0.0.1")
	commit(created, e)
	q := organization.DynamicRoleReadRequest{Authentication: owner, OrganizationID: org, RoleID: role, TargetUserID: memberID, CorrelationID: "roles"}
	v, e := s.GetDynamicRole(ctx, q)
	if e != nil || v.DynamicRole.Version != 1 || v.Organization.Version != 3 {
		t.Fatal("genuine role read", e)
	}
	current := func() organization.View {
		t.Helper()
		v, e := s.GetDynamicRole(ctx, q)
		if e != nil {
			t.Fatal("genuine current binding discovery", e)
		}
		return v
	}
	epoch := func() uint64 {
		t.Helper()
		v, e := s.Get(ctx, organization.ReadRequest{Authentication: q.Authentication, OrganizationID: org, CorrelationID: "roles"})
		if e != nil {
			t.Fatal("genuine policy discovery", e)
		}
		return v.Organization.Version
	}
	bindingRequest := func(v organization.View) organization.RoleBindingRequest {
		return organization.RoleBindingRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: org, RoleID: role, UserID: memberID, OrganizationVersion: v.Organization.Version, RoleVersion: v.DynamicRole.Version, OrganizationMemberVersion: v.Target.Version, BindingVersion: v.RoleBinding.Version, CorrelationID: "roles"}
	}
	page, e := s.ListDynamicRoles(ctx, organization.DynamicRoleReadRequest{Authentication: owner, OrganizationID: org, Limit: 1, CorrelationID: "roles"})
	if e != nil || len(page.DynamicRoles) != 1 || page.DynamicRoles[0].ID != role {
		t.Fatal("genuine role list", e)
	}
	b := bindingRequest(current())
	staleEpoch := b.OrganizationVersion
	commit(s.PrepareAssignDynamicRole(ctx, b, "127.0.0.1"))
	check := organization.PermissionCheckRequest{Authentication: member, OrganizationID: org, OrganizationVersion: epoch(), Action: "document.read", ResourceType: "document", ResourceID: "document-one", CorrelationID: "roles"}
	assert := func(want authorization.Outcome) {
		t.Helper()
		d, e := s.CheckPermission(ctx, check)
		if e != nil || d.Outcome != want || d.Revision != authorization.Revision(check.OrganizationVersion) {
			t.Fatalf("genuine permission %s: %+v %v", want, d, e)
		}
	}
	assert(authorization.Allow)
	if _, e = s.CheckPermission(ctx, organization.PermissionCheckRequest{Authentication: member, OrganizationID: org, OrganizationVersion: staleEpoch, Action: check.Action, ResourceType: check.ResourceType, ResourceID: check.ResourceID, CorrelationID: "stale"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("stale policy granted", e)
	}
	check.ResourceID = "document-two"
	assert(authorization.Deny)
	check.ResourceID = "document-one"
	r.CommandID = commandID(t)
	v = current()
	r.OrganizationVersion = v.Organization.Version
	r.RoleVersion = v.DynamicRole.Version
	r.Statements = append(r.Statements, organization.RoleStatement{PermissionID: "document-read", ResourceID: "document-one", Effect: authorization.Deny})
	commit(s.PrepareUpdateDynamicRole(ctx, r, "127.0.0.1"))
	check.OrganizationVersion = epoch()
	assert(authorization.Deny)
	r.CommandID = commandID(t)
	v = current()
	r.OrganizationVersion = v.Organization.Version
	r.RoleVersion = v.DynamicRole.Version
	r.Statements = []organization.RoleStatement{{PermissionID: "document-write", ResourceID: "document-one", Effect: authorization.Allow}}
	commit(s.PrepareUpdateDynamicRole(ctx, r, "127.0.0.1"))
	check.OrganizationVersion = epoch()
	assert(authorization.Deny)
	check.Action = "document.write"
	assert(authorization.Allow)
	// New clients use the native read API and a separately issued genuine
	// session; no command history or hardcoded binding/role epoch is retained.
	s = fresh()
	q.Authentication = recoveryOwner
	v = current()
	if !v.RoleBinding.Active {
		t.Fatal("fresh genuine manager did not discover live binding")
	}
	b = bindingRequest(v)
	commit(s.PrepareRevokeDynamicRole(ctx, b, "127.0.0.1"))
	check.OrganizationVersion = epoch()
	assert(authorization.Deny)
	s = fresh()
	v = current()
	if v.RoleBinding.Active || v.RoleBinding.Version == 0 {
		t.Fatal("fresh genuine manager did not discover binding tombstone")
	}
	b = bindingRequest(v)
	commit(s.PrepareAssignDynamicRole(ctx, b, "127.0.0.1"))
	check.OrganizationVersion = epoch()
	assert(authorization.Allow)
	r.CommandID = commandID(t)
	v = current()
	r.OrganizationVersion = v.Organization.Version
	r.RoleVersion = v.DynamicRole.Version
	r.Name = ""
	r.Statements = nil
	deleted, e := s.PrepareDeleteDynamicRole(ctx, r, "127.0.0.1")
	commit(deleted, e)
	check.OrganizationVersion = epoch()
	assert(authorization.Deny)
	if _, e = s.GetDynamicRole(ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("deleted role disclosed live", e)
	}
	handle, e := deleted.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.Recover(ctx, recoveryOwner, handle)
	if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
		t.Fatal("genuine role recovery", e)
	}
}
