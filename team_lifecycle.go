package organization

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// UpdateTeamRequest replaces only the bounded Name. Both epochs must match;
// identical names conflict without advancing epochs or emitting effects.
type UpdateTeamRequest struct {
	Authentication                   Authentication
	CommandID                        identity.CommandID
	OrganizationID, TeamID           ID
	OrganizationVersion, TeamVersion uint64
	Name, CorrelationID              string
}

// DeleteTeamRequest permanently retires this team identity at exact epochs.
// Existing member bindings cease to grant access without per-member fan-out;
// recreating the ID is forbidden. Historical command recovery remains separate.
type DeleteTeamRequest struct {
	Authentication                   Authentication
	CommandID                        identity.CommandID
	OrganizationID, TeamID           ID
	OrganizationVersion, TeamVersion uint64
	CorrelationID                    string
}

func (s *Service) GetTeam(ctx context.Context, r TeamReadRequest) (View, error) {
	return s.readTeams(ctx, r, GetTeam)
}
func (s *Service) PrepareUpdateTeam(ctx context.Context, r UpdateTeamRequest) (Command, error) {
	return s.prepareTeamLifecycle(ctx, r, UpdateTeam)
}
func (s *Service) PrepareDeleteTeam(ctx context.Context, r DeleteTeamRequest) (Command, error) {
	return s.prepareTeamLifecycle(ctx, UpdateTeamRequest{Authentication: r.Authentication, CommandID: r.CommandID, OrganizationID: r.OrganizationID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion, TeamVersion: r.TeamVersion, CorrelationID: r.CorrelationID}, DeleteTeam)
}

func (s *Service) prepareTeamLifecycle(ctx context.Context, r UpdateTeamRequest, op Operation) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || s.config.Teams.LifecycleVersion != 1 || !safeID(string(r.OrganizationID)) || !safeID(string(r.TeamID)) || !safeID(r.CorrelationID) || r.OrganizationVersion == 0 || r.OrganizationVersion == ^uint64(0) || r.TeamVersion == 0 || r.TeamVersion == ^uint64(0) || op == UpdateTeam && !boundedText(r.Name, 256) {
		return out, ErrInvalidInput
	}
	if _, err = identity.ParseCommandID(string(r.CommandID)); err != nil {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil || s.config.ValidateCanonicalID(bounded, r.TeamID) != nil {
		return out, ErrInvalidInput
	}
	observed, actor, err := s.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	v, err := s.repository.Read(bounded, Query{Operation: op, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, TeamID: r.TeamID})
	if err != nil {
		return out, publicError(bounded, err)
	}
	if !validView(v, r.Authentication.TenantID, r.OrganizationID, actor) || v.Actor.Role != RoleOwner && v.Actor.Role != RoleAdministrator || !validTeam(v.Team, r.Authentication.TenantID, r.OrganizationID) || v.Team.ID != r.TeamID {
		return out, ErrForbidden
	}
	if err = s.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, op, r.CorrelationID); err != nil {
		return out, err
	}
	if v.Organization.Version != r.OrganizationVersion || v.Team.Version != r.TeamVersion || op == UpdateTeam && v.Team.Name == r.Name {
		return out, ErrConflict
	}
	if op == UpdateTeam {
		v.Team.Name = strings.Clone(r.Name)
	}
	if err = bounded.Err(); err != nil {
		return out, err
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	out = s.command(r.CommandID, op, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, Member{}, identity.User{ID: actor, TenantID: r.Authentication.TenantID}, "")
	out.state.input.Binding.SchemaID = op.Descriptor().SchemaID
	out.state.input.Team, out.state.input.Teams = v.Team, s.config.Teams
	return out, nil
}
