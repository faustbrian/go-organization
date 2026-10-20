package organization

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// TeamRoleBinding is one organization-scoped custom-role assignment to a
// terminal team identity. Active is stored assignment state, not a membership
// grant: effective access also requires current compatible org/team membership.
// Version zero denotes never assigned; revoked bindings retain their version.
type TeamRoleBinding struct {
	RoleID, TeamID, OrganizationID ID
	TenantID                       identity.TenantID
	Version                        uint64
	Active                         bool
}

// TeamRoleBindingRequest assigns/revokes one role for an exact current team.
// OrganizationVersion, RoleVersion, TeamVersion and BindingVersion are obtained
// from GetDynamicRole with TargetTeamID, including retained binding tombstones.
// It never names or impersonates a human target and confers no manager authority.
type TeamRoleBindingRequest struct {
	Authentication                                                Authentication
	CommandID                                                     identity.CommandID
	OrganizationID, RoleID, TeamID                                ID
	OrganizationVersion, RoleVersion, TeamVersion, BindingVersion uint64
	CorrelationID                                                 string
}

// PrepareAssignTeamDynamicRole freezes a team-targeted role.assign command.
// TeamBindingsVersion1 and terminal team lifecycle must be selected explicitly.
func (s *Service) PrepareAssignTeamDynamicRole(ctx context.Context, r TeamRoleBindingRequest) (Command, error) {
	return s.prepareTeamRole(ctx, r, AssignDynamicRole)
}

// PrepareRevokeTeamDynamicRole freezes removal of one exact team-role binding.
func (s *Service) PrepareRevokeTeamDynamicRole(ctx context.Context, r TeamRoleBindingRequest) (Command, error) {
	return s.prepareTeamRole(ctx, r, RevokeDynamicRole)
}

func (s *Service) prepareTeamRole(ctx context.Context, r TeamRoleBindingRequest, op Operation) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || s.config.DynamicRoles.TeamBindingsVersion != 1 || !safeID(string(r.OrganizationID)) || !safeID(string(r.RoleID)) || Role(r.RoleID).Valid() || !safeID(string(r.TeamID)) || !safeID(r.CorrelationID) || r.OrganizationVersion == 0 || r.OrganizationVersion == ^uint64(0) || r.RoleVersion == 0 || r.RoleVersion == ^uint64(0) || r.TeamVersion == 0 || r.TeamVersion == ^uint64(0) || r.BindingVersion == ^uint64(0) || op == RevokeDynamicRole && r.BindingVersion == 0 {
		return out, ErrInvalidInput
	}
	if _, e := identity.ParseCommandID(string(r.CommandID)); e != nil {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	for _, id := range []ID{r.OrganizationID, r.RoleID, r.TeamID} {
		if s.config.ValidateCanonicalID(bounded, id) != nil {
			return out, ErrInvalidInput
		}
	}
	observed, actor, e := s.authenticate(bounded, r.Authentication)
	if e != nil {
		return out, e
	}
	q := Query{Operation: op, TenantID: r.Authentication.TenantID, OrganizationID: r.OrganizationID, ActorID: actor, DynamicRoleID: r.RoleID, TeamID: r.TeamID}
	v, e := s.repository.Read(bounded, q)
	if e != nil {
		return out, publicError(bounded, e)
	}
	if !validView(v, q.TenantID, q.OrganizationID, actor) || v.Actor.Role != RoleOwner && v.Actor.Role != RoleAdministrator || !validDynamicRole(v.DynamicRole, q.TenantID, q.OrganizationID) || v.DynamicRole.ID != r.RoleID || !validTeamRoleView(v, q) {
		return out, ErrForbidden
	}
	if e = s.authorize(bounded, actor, q.TenantID, q.OrganizationID, v.Organization.Version, op, r.CorrelationID); e != nil {
		return out, e
	}
	if v.Organization.Version != r.OrganizationVersion || v.DynamicRole.Version != r.RoleVersion || v.Team.Version != r.TeamVersion || v.TeamRoleBinding.Version != r.BindingVersion {
		return out, ErrConflict
	}
	if op == AssignDynamicRole && v.TeamRoleBinding.Active {
		return out, ErrConflict
	}
	if op == RevokeDynamicRole && !v.TeamRoleBinding.Active {
		return out, ErrForbidden
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	if e = bounded.Err(); e != nil {
		return out, e
	}
	out = s.command(r.CommandID, op, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, Member{}, identity.User{ID: actor, TenantID: q.TenantID}, "")
	out.state.input.Binding.SchemaID = op.Descriptor().SchemaID
	v.DynamicRole.Statements = nil
	out.state.input.DynamicRole = v.DynamicRole
	out.state.input.Team = v.Team
	out.state.input.TeamRoleBinding = v.TeamRoleBinding
	out.state.input.DynamicRoles = s.config.DynamicRoles.clone()
	return out, nil
}

func validTeamRoleView(v View, q Query) bool {
	b := v.TeamRoleBinding
	return validTeam(v.Team, q.TenantID, q.OrganizationID) && v.Team.ID == q.TeamID && b.TenantID == q.TenantID && b.OrganizationID == q.OrganizationID && b.TeamID == q.TeamID && b.RoleID == q.DynamicRoleID && (b.Version > 0 || !b.Active)
}
