//go:build integration

package postgres_test

import (
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestDynamicRoleTerminalReplayRequiresCurrentManager(t *testing.T) {
	for _, op := range []organization.Operation{organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole, organization.AssignDynamicRole, organization.RevokeDynamicRole} {
		for _, withdrawal := range []string{"demoted", "removed", "session-revoked"} {
			t.Run(string(op)+"/"+withdrawal, func(t *testing.T) {
				f := dynamicRoleFixture(t)
				f.create(t, "org-test-basic")
				f.add(t, "org-test-basic", "second", organization.RoleAdministrator, 1)
				f.add(t, "org-test-basic", "member", organization.RoleMember, 2)
				r := dynamicRoleRequest(t, f, 3)
				r.Authentication = f.auth("org-test-basic", "second")
				p, e := f.service.PrepareCreateDynamicRole(f.ctx, r, "127.0.0.1")
				commitRole(t, f, p, e)
				epoch := uint64(4)
				if op != organization.CreateDynamicRole {
					r.CommandID = commandID(t)
					r.OrganizationVersion = epoch
					r.RoleVersion = 1
					if op == organization.UpdateDynamicRole {
						r.Name = "Renamed"
						p, e = f.service.PrepareUpdateDynamicRole(f.ctx, r, "127.0.0.1")
					} else if op == organization.DeleteDynamicRole {
						r.Name = ""
						r.Statements = nil
						p, e = f.service.PrepareDeleteDynamicRole(f.ctx, r, "127.0.0.1")
					} else {
						b := roleBindingRequest(t, f, epoch)
						b.Authentication = r.Authentication
						p, e = f.service.PrepareAssignDynamicRole(f.ctx, b, "127.0.0.1")
						if op == organization.RevokeDynamicRole {
							commitRole(t, f, p, e)
							epoch++
							b.CommandID = commandID(t)
							b.OrganizationVersion = epoch
							b.BindingVersion = 1
							p, e = f.service.PrepareRevokeDynamicRole(f.ctx, b, "127.0.0.1")
						}
					}
					commitRole(t, f, p, e)
					epoch++
				}
				switch withdrawal {
				case "demoted":
					change, e := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, "org-test-basic", "owner", "second", epoch, 1, organization.RoleMember), "127.0.0.1")
					commitRole(t, f, change, e)
				case "removed":
					change, e := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: epoch, UserID: "second", MemberVersion: 1, CorrelationID: "replay-withdrawal"}, "127.0.0.1")
					commitRole(t, f, change, e)
				case "session-revoked":
					if _, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='second'`); e != nil {
						t.Fatal(e)
					}
				}
				// fixturePolicy still explicitly allows the original operation. The
				// original observation is unexpired; current native authority must veto.
				got, e := f.service.Execute(f.ctx, p)
				if !errors.Is(e, organization.ErrForbidden) || got != (organization.StoreResult{}) {
					t.Fatalf("withdrawn manager received terminal role receipt: %v %v", got.Receipt.Outcome, e)
				}
				var count int
				if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE command_id=$1`, string(mustRoleRecovery(t, p).Binding.CommandID)).Scan(&count); e != nil || count != 1 {
					t.Fatal("denied replay changed effects", e)
				}
			})
		}
	}
}

func mustRoleRecovery(t *testing.T, p organizationpg.PreparedCommand) organizationpg.Recovery {
	t.Helper()
	r, e := p.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestDynamicRoleFreshManagerDiscoversBindingVersions(t *testing.T) {
	f := dynamicRoleFixture(t)
	f.create(t, "org-test-basic")
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	f.add(t, "org-test-basic", "second", organization.RoleAdministrator, 2)
	p := prepareRole(t, f, 3)
	commitRole(t, f, p, nil)
	q := organization.DynamicRoleReadRequest{Authentication: f.auth("org-test-basic", "second"), OrganizationID: metadataOrganization, RoleID: "reader", TargetUserID: "member", CorrelationID: "binding-discovery"}
	current, e := f.service.GetDynamicRole(f.ctx, q)
	if e != nil || current.Target.UserID != "member" || !current.Target.Active || current.RoleBinding.UserID != "member" || current.RoleBinding.Version != 0 || current.RoleBinding.Active {
		t.Fatal("manager cannot discover an absent exact binding", e)
	}
	request := func(v organization.View) organization.RoleBindingRequest {
		return organization.RoleBindingRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: q.OrganizationID, RoleID: q.RoleID, UserID: q.TargetUserID, OrganizationVersion: v.Organization.Version, RoleVersion: v.DynamicRole.Version, OrganizationMemberVersion: v.Target.Version, BindingVersion: v.RoleBinding.Version, CorrelationID: "binding-discovery"}
	}
	p, e = f.service.PrepareAssignDynamicRole(f.ctx, request(current), "127.0.0.1")
	commitRole(t, f, p, e)
	// A reconstructed public service has no retained command/application history.
	client, e := organizationpg.NewService(f.participant, f.configuration)
	if e != nil {
		t.Fatal(e)
	}
	current, e = client.GetDynamicRole(f.ctx, q)
	if e != nil || !current.RoleBinding.Active || current.RoleBinding.Version == 0 || current.RoleBinding.OrganizationMemberVersion != current.Target.Version {
		t.Fatal("fresh manager cannot discover live binding", e)
	}
	p, e = client.PrepareRevokeDynamicRole(f.ctx, request(current), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = client.Execute(f.ctx, p); e != nil {
		t.Fatal(e)
	}
	client, e = organizationpg.NewService(f.participant, f.configuration)
	if e != nil {
		t.Fatal(e)
	}
	current, e = client.GetDynamicRole(f.ctx, q)
	if e != nil || current.RoleBinding.Active || current.RoleBinding.Version == 0 {
		t.Fatal("fresh manager cannot discover revoked binding tombstone", e)
	}
	p, e = client.PrepareAssignDynamicRole(f.ctx, request(current), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = client.Execute(f.ctx, p); e != nil {
		t.Fatal(e)
	}
	current, e = client.GetDynamicRole(f.ctx, q)
	if e != nil {
		t.Fatal(e)
	}
	d, e := client.CheckPermission(f.ctx, organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: q.OrganizationID, OrganizationVersion: current.Organization.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "binding-discovery"})
	if e != nil || d.Outcome != authorization.Allow {
		t.Fatal("discovered tombstone could not reassign real permission", e)
	}
	list := q
	list.RoleID = ""
	list.Limit = 10
	if _, e = client.ListDynamicRoles(f.ctx, list); !errors.Is(e, organization.ErrInvalidInput) {
		t.Fatal("list accepted target binding selector", e)
	}
	for _, foreign := range []organization.DynamicRoleReadRequest{
		{Authentication: f.auth("org-test-scope", "owner"), OrganizationID: q.OrganizationID, RoleID: q.RoleID, TargetUserID: q.TargetUserID, CorrelationID: "binding-scope"},
		{Authentication: q.Authentication, OrganizationID: "foreign-org", RoleID: q.RoleID, TargetUserID: q.TargetUserID, CorrelationID: "binding-scope"},
		{Authentication: q.Authentication, OrganizationID: q.OrganizationID, RoleID: q.RoleID, TargetUserID: "outsider", CorrelationID: "binding-scope"},
	} {
		if _, e = client.GetDynamicRole(f.ctx, foreign); !errors.Is(e, organization.ErrForbidden) {
			t.Fatal("foreign binding metadata disclosed", e)
		}
	}
	// Membership tombstones remain explicit even when a retained assignment
	// still has its stored active flag. Reads never equate that flag with access.
	remove, e := client.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: q.OrganizationID, OrganizationVersion: current.Organization.Version, MemberVersion: current.Target.Version, UserID: q.TargetUserID, CorrelationID: "binding-removal"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = client.Execute(f.ctx, remove); e != nil {
		t.Fatal(e)
	}
	current, e = client.GetDynamicRole(f.ctx, q)
	if e != nil || current.Target.Active || !current.RoleBinding.Active || current.RoleBinding.OrganizationMemberVersion >= current.Target.Version {
		t.Fatal("removed target membership state was hidden or inferred from binding", e)
	}
	readmit, e := client.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: q.OrganizationID, OrganizationVersion: current.Organization.Version, MemberVersion: current.Target.Version, UserID: q.TargetUserID, Role: organization.RoleMember, CorrelationID: "binding-readmission"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = client.Execute(f.ctx, readmit); e != nil {
		t.Fatal(e)
	}
	current, e = client.GetDynamicRole(f.ctx, q)
	if e != nil || !current.Target.Active || current.RoleBinding.OrganizationMemberVersion == current.Target.Version {
		t.Fatal("readmitted membership revived stored binding", e)
	}
	d, e = client.CheckPermission(f.ctx, organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: q.OrganizationID, OrganizationVersion: current.Organization.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "binding-readmission"})
	if e != nil || d.Outcome != authorization.Deny {
		t.Fatal("binding metadata was mistaken for current authority", e)
	}
}

func TestDynamicRoleBindingReadDeniesWithdrawnManager(t *testing.T) {
	for _, withdrawal := range []string{"demoted", "removed", "session-revoked"} {
		t.Run(withdrawal, func(t *testing.T) {
			f := dynamicRoleFixture(t)
			f.create(t, "org-test-basic")
			f.add(t, "org-test-basic", "second", organization.RoleAdministrator, 1)
			f.add(t, "org-test-basic", "member", organization.RoleMember, 2)
			p := prepareRole(t, f, 3)
			commitRole(t, f, p, nil)
			q := organization.DynamicRoleReadRequest{Authentication: f.auth("org-test-basic", "second"), OrganizationID: metadataOrganization, RoleID: "reader", TargetUserID: "member", CorrelationID: "binding-withdrawal"}
			if _, e := f.service.GetDynamicRole(f.ctx, q); e != nil {
				t.Fatal("current manager read failed", e)
			}
			switch withdrawal {
			case "demoted":
				p, e := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, "org-test-basic", "owner", "second", 4, 1, organization.RoleMember), "127.0.0.1")
				commitRole(t, f, p, e)
			case "removed":
				p, e := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 4, MemberVersion: 1, UserID: "second", CorrelationID: "binding-withdrawal"}, "127.0.0.1")
				commitRole(t, f, p, e)
			case "session-revoked":
				if _, e := f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='second'`); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := f.service.GetDynamicRole(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
				t.Fatal("withdrawn manager discovered binding", e)
			}
		})
	}
}
