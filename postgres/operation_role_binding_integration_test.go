//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func directRoleBindingFixture(t *testing.T, optional bool) (*orgFixture, organization.AssignDynamicRoleOperationRequest) {
	t.Helper()
	f := dynamicRoleOperationFixture(t, false)
	if optional {
		installDirectRoleBindingMigration(t, f)
	}
	r := createRoleOperationRequest(t, f)
	if _, err := slugNativeOperationService(t, f.service).CreateDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("original-direct-role-assignment"))
	if err != nil {
		t.Fatal(err)
	}
	return f, organization.AssignDynamicRoleOperationRequest{Authentication: r.Authentication, IdempotencyKey: key, OrganizationID: r.OrganizationID, RoleID: r.RoleID, UserID: "member", OrganizationVersion: 3, RoleVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "original-direct-role-assignment"}
}

func installDirectRoleBindingMigration(t *testing.T, f *orgFixture) {
	t.Helper()
	installDynamicRoleOperationSources(t, f, organizationpg.DynamicRoleMigrationSource{Version: 305}, organizationpg.TeamRoleBindingMigrationSource{Version: 306}, organizationpg.RoleBindingRevokeOperationLookupMigrationSource{Version: 324})
}

func revokeDirectRoleBindingRequest(r organization.AssignDynamicRoleOperationRequest) organization.RevokeDynamicRoleOperationRequest {
	return organization.RevokeDynamicRoleOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, UserID: r.UserID, OrganizationVersion: r.OrganizationVersion + 1, RoleVersion: r.RoleVersion, OrganizationMemberVersion: r.OrganizationMemberVersion, BindingVersion: r.BindingVersion + 1, CorrelationID: "natural-direct-role-revoke"}
}

type directRoleBindingPolicy struct {
	before                func(context.Context, authorization.DecisionContext) error
	denyAction, denyQuery bool
	queries               atomic.Int32
}

func (p *directRoleBindingPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == authorization.Action(organization.Get) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
	}
	if c.Request.Action == authorization.Action(organization.AssignDynamicRole) || c.Request.Action == authorization.Action(organization.RevokeDynamicRole) {
		if c.Request.Resource.Type == "organization" && p.denyAction {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
		}
		if c.Request.Resource.Type == "identity.user" {
			p.queries.Add(1)
			if p.denyQuery {
				return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
			}
		}
		if p.before != nil {
			if err := p.before(ctx, c); err != nil {
				return authorization.Decision{}, err
			}
		}
	}
	return (fixturePolicy{}).Decide(ctx, c)
}

func TestDirectRoleBindingOperationOriginalPermissionAndNoOrganizationRead(t *testing.T) {
	f, r := directRoleBindingFixture(t, true)
	s := leaveOperationPolicyFacade(t, f, new(directRoleBindingPolicy), nil)
	if _, err := s.Get(f.ctx, organization.ReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, CorrelationID: "deny-unrelated-read"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("org read not actually denied", err)
	}
	assigned, err := s.AssignDynamicRole(f.ctx, r, "127.0.0.1")
	if err != nil || assigned.Receipt.Feature == nil || assigned.Receipt.Feature.BeforeVersion != 3 || assigned.Receipt.Feature.AfterVersion != 4 || assigned.Receipt.Binding.UserID != r.UserID {
		t.Fatal("actual original direct assignment", err)
	}
	if out, err := s.AssignDynamicRole(f.ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, assigned) {
		t.Fatal("original assign required unrelated read or changed outcome", err)
	}
	q := organization.DynamicRoleReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TargetUserID: r.UserID, CorrelationID: "discover-direct-binding"}
	v, err := s.GetDynamicRole(f.ctx, q)
	if err != nil || !v.RoleBinding.Active || v.RoleBinding.Version != 1 || v.RoleBinding.OrganizationMemberVersion != 1 || v.DynamicRole.Version != 1 || v.Target.Version != 1 {
		t.Fatal("actual binding selectors differ", err)
	}
	permission := organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: r.OrganizationID, OrganizationVersion: 4, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "effective-direct-role"}
	if d, err := s.CheckPermission(f.ctx, permission); err != nil || d.Outcome != authorization.Allow {
		t.Fatal("actual assigned target permission", err)
	}
	x := revokeDirectRoleBindingRequest(r)
	revoked, err := s.RevokeDynamicRole(f.ctx, x, "127.0.0.1")
	if err != nil || revoked.Receipt.Feature == nil || revoked.Receipt.Feature.BeforeVersion != 4 || revoked.Receipt.Feature.AfterVersion != 5 {
		t.Fatal("actual exact revocation", err)
	}
	permission.OrganizationVersion = 5
	if d, err := s.CheckPermission(f.ctx, permission); err != nil || d.Outcome != authorization.Deny {
		t.Fatal("actual revoked target permission", err)
	}
	v, err = s.GetDynamicRole(f.ctx, q)
	if err != nil || v.RoleBinding.Active || v.RoleBinding.Version != 2 || v.RoleBinding.OrganizationMemberVersion != 1 {
		t.Fatal("binding tombstone differs", err)
	}
	for range 2 {
		if out, err := leaveOperationPolicyFacade(t, f, new(directRoleBindingPolicy), nil).RevokeDynamicRole(f.ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, revoked) {
			t.Fatal("reconstructed natural original differs", err)
		}
	}
	for _, original := range []organization.StoreResult{assigned, revoked} {
		if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, original) {
			t.Fatal("nonself original recovery required unrelated org read", err)
		}
	}
	config := f.configuration
	config.Authorization = new(directRoleBindingPolicy)
	legacy, err := organizationpg.NewService(f.participant, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Recover(f.ctx, r.Authentication, organizationpg.Recovery{Binding: assigned.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("raw legacy recovery authority changed", err)
	}
	// A new assignment consumes the exact tombstone version and does not let an
	// old natural revocation reach the newer grant, even under current managers.
	r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("new-direct-role-assignment"))
	r.OrganizationVersion = 5
	r.BindingVersion = 2
	if _, err := s.AssignDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if out, err := s.RevokeDynamicRole(f.ctx, x, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out != (organization.StoreResult{}) {
		t.Fatal("old revoke reached new assignment", err)
	}
	permission.OrganizationVersion = 6
	if d, err := s.CheckPermission(f.ctx, permission); err != nil || d.Outcome != authorization.Allow {
		t.Fatal("new grant was changed by old revoke", err)
	}
}

func TestDirectRoleBindingOperationExactKeyIntent(t *testing.T) {
	f, r := directRoleBindingFixture(t, true)
	s := slugNativeOperationService(t, f.service)
	if _, err := s.AssignDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"organization", "role", "target", "org-epoch", "role-epoch", "member-epoch", "binding-epoch"} {
		t.Run(field, func(t *testing.T) {
			changed := r
			switch field {
			case "organization":
				changed.OrganizationID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
			case "role":
				changed.RoleID = "other-role"
			case "target":
				changed.UserID = "outsider"
			case "org-epoch":
				changed.OrganizationVersion++
			case "role-epoch":
				changed.RoleVersion++
			case "member-epoch":
				changed.OrganizationMemberVersion++
			case "binding-epoch":
				changed.BindingVersion++
			}
			if out, err := s.AssignDynamicRole(f.ctx, changed, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out != (organization.StoreResult{}) {
				t.Fatal("changed assignment intent accepted", err)
			}
		})
	}
	changed := r
	changed.CorrelationID = "diagnostic-only"
	if _, err := s.AssignDynamicRole(f.ctx, changed, "127.0.0.1"); err != nil {
		t.Fatal("correlation changed immutable intent", err)
	}
}

func TestDirectRoleBindingOperationLegacyWritersNeedNoOptionalSchema(t *testing.T) {
	f, r := directRoleBindingFixture(t, false)
	s := slugNativeOperationService(t, f.service)
	assigned, err := s.AssignDynamicRole(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal("keyed assignment imposed optional revoke schema", err)
	}
	x := revokeDirectRoleBindingRequest(r)
	if out, err := s.RevokeDynamicRole(f.ctx, x, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("natural revoke ran without selected lookup schema", err)
	}
	p, err := f.service.PrepareRevokeDynamicRole(f.ctx, organization.RoleBindingRequest{Authentication: x.Authentication, CommandID: commandID(t), OrganizationID: x.OrganizationID, RoleID: x.RoleID, UserID: x.UserID, OrganizationVersion: x.OrganizationVersion, RoleVersion: x.RoleVersion, OrganizationMemberVersion: x.OrganizationMemberVersion, BindingVersion: x.BindingVersion, CorrelationID: x.CorrelationID}, "127.0.0.1")
	commitRole(t, f, p, err)
	installDirectRoleBindingMigration(t, f)
	if out, err := s.RevokeDynamicRole(f.ctx, x, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("uncorrelated legacy tombstone invented original success", err)
	}
	if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: assigned.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, assigned) {
		t.Fatal("legacy schema changed original assign recovery", err)
	}
}

func TestDirectRoleBindingOperationReadmissionDoesNotReviveGrant(t *testing.T) {
	f, r := directRoleBindingFixture(t, true)
	s := slugNativeOperationService(t, f.service)
	if _, err := s.AssignDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	x := revokeDirectRoleBindingRequest(r)
	original, err := s.RevokeDynamicRole(f.ctx, x, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 5, UserID: r.UserID, MemberVersion: 1, CorrelationID: "remove-admission"}, "127.0.0.1")
	commitRole(t, f, p, err)
	p, err = f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 6, UserID: r.UserID, MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "new-admission"}, "127.0.0.1")
	commitRole(t, f, p, err)
	q := organization.DynamicRoleReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TargetUserID: r.UserID, CorrelationID: "readmitted-binding"}
	v, err := s.GetDynamicRole(f.ctx, q)
	if err != nil || v.Target.Version != 3 || v.RoleBinding.Active || v.RoleBinding.OrganizationMemberVersion != 1 {
		t.Fatal("readmission revived old binding", err)
	}
	if out, err := s.RevokeDynamicRole(f.ctx, x, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out != (organization.StoreResult{}) {
		t.Fatal("old natural revoke reached new admission", err)
	}
	if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, original) {
		t.Fatal("current manager could not disclose actual old receipt", err)
	}
	check := organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: r.OrganizationID, OrganizationVersion: 7, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "no-readmission-grant"}
	if d, err := s.CheckPermission(f.ctx, check); err != nil || d.Outcome != authorization.Deny {
		t.Fatal("readmission revived effective permission", err)
	}
}
