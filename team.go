package organization

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

const (
	CreateTeam       Operation = "identity.organization.team.create"
	AddTeamMember    Operation = "identity.organization.team.member-add"
	RemoveTeamMember Operation = "identity.organization.team.member-remove"
	GetTeam          Operation = "identity.organization.team.get"
	UpdateTeam       Operation = "identity.organization.team.update"
	DeleteTeam       Operation = "identity.organization.team.delete"
	ListTeams        Operation = "identity.organization.team.list"
	ListMyTeams      Operation = "identity.organization.team.list-mine"
	ListTeamMembers  Operation = "identity.organization.team.member-list"
)

// TeamConfig explicitly selects the finite membership-only profile. Zero disables
// it. Version identifies the immutable deployed team policy; quotas have no
// defaults. Teams never grant organization roles or independent permissions.
// MaximumTeams follows REFERENCE_CONFIGURATION organization.max_teams (10,000).
// MaximumMembers is a local storage/cardinality budget capped at the existing
// 100,000 organization-member ceiling, not a protocol-defined team default.
type TeamConfig struct {
	Version, MaximumTeams, MaximumMembers uint64
	// LifecycleVersion 1 selects get/update/terminal-delete after the native
	// forward migration. Zero preserves the original membership-only profile
	// and its serialized configuration and command framing.
	LifecycleVersion uint64 `json:",omitempty"`
}

func (c TeamConfig) Validate() error {
	if c == (TeamConfig{}) {
		return nil
	}
	if c.Version == 0 || c.MaximumTeams < 1 || c.MaximumTeams > 10000 || c.MaximumMembers < 1 || c.MaximumMembers > 100000 || c.LifecycleVersion > 1 {
		return ErrInvalidInput
	}
	return nil
}

// Team is a tenant/organization-bound snapshot. Version advances on membership
// changes; Organization.Version is the shared policy epoch, not this local value.
type Team struct {
	ID, OrganizationID ID
	TenantID           identity.TenantID
	Name               string
	Version            uint64
}

// TeamMember retains removal tombstones. OrganizationMemberVersion binds the
// exact admission, so removing and readmitting an org member cannot revive teams.
type TeamMember struct {
	TeamID, OrganizationID             ID
	TenantID                           identity.TenantID
	UserID                             identity.UserID
	Version, OrganizationMemberVersion uint64
	Active                             bool
}

// CreateTeamRequest creates a named bounded team without adding members.
// IDs preserve canonical caller identities and are unique within an organization.
type CreateTeamRequest struct {
	Authentication         Authentication
	CommandID              identity.CommandID
	OrganizationID, TeamID ID
	OrganizationVersion    uint64
	Name, CorrelationID    string
}

// TeamMemberRequest binds exact organization/team/member epochs. Add requires
// zero MembershipVersion for a never-bound user or the previous tombstone version.
// Remove requires the current binding; replay uses the original prepared command.
type TeamMemberRequest struct {
	Authentication                                                                 Authentication
	CommandID                                                                      identity.CommandID
	OrganizationID, TeamID                                                         ID
	UserID                                                                         identity.UserID
	OrganizationVersion, TeamVersion, OrganizationMemberVersion, MembershipVersion uint64
	CorrelationID                                                                  string
}

// TeamReadRequest selects an exact team or a paginated team read. GetTeam
// requires TeamID, Limit zero, and an empty Cursor. Paginated reads use exclusive
// bytewise ID keysets, 1..100 per page; only ListTeamMembers requires TeamID.
// Members may read their own team's members; only owners/admins may read all
// organization teams or other teams.
type TeamReadRequest struct {
	Authentication         Authentication
	OrganizationID, TeamID ID
	Cursor                 string
	Limit                  uint32
	CorrelationID          string
}

func teamMutation(op Operation) bool {
	return op == CreateTeam || op == AddTeamMember || op == RemoveTeamMember || op == UpdateTeam || op == DeleteTeam
}
func (s *Service) PrepareCreateTeam(ctx context.Context, r CreateTeamRequest) (Command, error) {
	return s.prepareTeam(ctx, r, TeamMemberRequest{}, CreateTeam)
}
func (s *Service) PrepareAddTeamMember(ctx context.Context, r TeamMemberRequest) (Command, error) {
	return s.prepareTeam(ctx, CreateTeamRequest{}, r, AddTeamMember)
}
func (s *Service) PrepareRemoveTeamMember(ctx context.Context, r TeamMemberRequest) (Command, error) {
	return s.prepareTeam(ctx, CreateTeamRequest{}, r, RemoveTeamMember)
}

func (s *Service) prepareTeam(ctx context.Context, create CreateTeamRequest, member TeamMemberRequest, op Operation) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	a, id, org, team, version, correlation := member.Authentication, member.CommandID, member.OrganizationID, member.TeamID, member.OrganizationVersion, member.CorrelationID
	if op == CreateTeam {
		a, id, org, team, version, correlation = create.Authentication, create.CommandID, create.OrganizationID, create.TeamID, create.OrganizationVersion, create.CorrelationID
	}
	if s == nil || ctx == nil || s.config.Teams.MaximumTeams == 0 || !safeID(string(org)) || !safeID(string(team)) || !safeID(correlation) || version == 0 || version == ^uint64(0) {
		return out, ErrInvalidInput
	}
	if _, err = identity.ParseCommandID(string(id)); err != nil {
		return out, ErrInvalidInput
	}
	if op == CreateTeam {
		if !boundedText(create.Name, 256) {
			return out, ErrInvalidInput
		}
	} else if !safeID(string(member.UserID)) || member.TeamVersion == 0 || member.TeamVersion == ^uint64(0) || member.OrganizationMemberVersion == 0 || member.MembershipVersion == ^uint64(0) || op == RemoveTeamMember && member.MembershipVersion == 0 {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, org) != nil || s.config.ValidateCanonicalID(bounded, team) != nil {
		return out, ErrInvalidInput
	}
	observed, actor, err := s.authenticate(bounded, a)
	if err != nil {
		return out, err
	}
	v, err := s.repository.Read(bounded, Query{Operation: op, TenantID: a.TenantID, ActorID: actor, OrganizationID: org, TeamID: team, TargetID: member.UserID})
	if err != nil {
		return out, publicError(bounded, err)
	}
	if !validView(v, a.TenantID, org, actor) || v.Actor.Role != RoleOwner && v.Actor.Role != RoleAdministrator {
		return out, ErrForbidden
	}
	if err = s.authorize(bounded, actor, a.TenantID, org, v.Organization.Version, op, correlation); err != nil {
		return out, err
	}
	if v.Organization.Version != version {
		return out, ErrConflict
	}
	user := identity.User{ID: actor, TenantID: a.TenantID}
	if op == CreateTeam {
		if v.Team.Version != 0 {
			return out, ErrConflict
		}
		v.Team = Team{ID: team, OrganizationID: org, TenantID: a.TenantID, Name: strings.Clone(create.Name)}
	} else {
		if !validTeam(v.Team, a.TenantID, org) || v.Team.ID != team || !v.Target.Active || v.Target.UserID != member.UserID || v.Target.OrganizationID != org || v.Target.TenantID != a.TenantID || v.TargetUser.Validate(a.TenantID) != nil || v.TargetUser.ID != member.UserID || v.TargetUser.Status != identity.StatusActive {
			return out, ErrForbidden
		}
		if v.Team.Version != member.TeamVersion || v.Target.Version != member.OrganizationMemberVersion || v.TeamMember.Version != member.MembershipVersion {
			return out, ErrConflict
		}
		current := v.TeamMember.Active && v.TeamMember.OrganizationMemberVersion == v.Target.Version
		if op == AddTeamMember && current {
			return out, ErrConflict
		}
		if op == RemoveTeamMember && !current {
			return out, ErrForbidden
		}
		user = v.TargetUser
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	if err = bounded.Err(); err != nil {
		return out, err
	}
	out = s.command(id, op, correlation, observed, a.Bearer, v.Organization, v.Actor, v.Target, user, "")
	out.state.input.Binding.SchemaID = op.Descriptor().SchemaID
	out.state.input.Team, out.state.input.TeamMember, out.state.input.Teams = v.Team, v.TeamMember, s.config.Teams
	return out, nil
}

func validTeam(t Team, tenant identity.TenantID, org ID) bool {
	return t.TenantID == tenant && t.OrganizationID == org && safeID(string(t.ID)) && boundedText(t.Name, 256) && t.Version > 0
}

func (s *Service) ListTeams(ctx context.Context, r TeamReadRequest) (View, error) {
	return s.readTeams(ctx, r, ListTeams)
}
func (s *Service) ListMyTeams(ctx context.Context, r TeamReadRequest) (View, error) {
	return s.readTeams(ctx, r, ListMyTeams)
}
func (s *Service) ListTeamMembers(ctx context.Context, r TeamReadRequest) (View, error) {
	return s.readTeams(ctx, r, ListTeamMembers)
}

func (s *Service) readTeams(ctx context.Context, r TeamReadRequest, op Operation) (out View, err error) {
	defer func() {
		if recover() != nil {
			out, err = View{}, ErrUnavailable
		}
	}()
	exact := op == GetTeam
	if s == nil || ctx == nil || s.config.Teams.MaximumTeams == 0 || !safeID(string(r.OrganizationID)) || !safeID(r.CorrelationID) || exact && (s.config.Teams.LifecycleVersion != 1 || r.Limit != 0 || r.Cursor != "") || !exact && (r.Limit < 1 || r.Limit > 100 || r.Cursor != "" && !safeID(r.Cursor)) || (op == ListTeamMembers || exact) && !safeID(string(r.TeamID)) || op != ListTeamMembers && !exact && r.TeamID != "" {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil || r.TeamID != "" && s.config.ValidateCanonicalID(bounded, r.TeamID) != nil {
		return out, ErrInvalidInput
	}
	_, actor, err := s.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	q := Query{Operation: op, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, TeamID: r.TeamID, TeamCursor: r.Cursor, Limit: r.Limit}
	out, err = s.repository.Read(bounded, q)
	if err != nil {
		return View{}, publicError(bounded, err)
	}
	if !validView(out, q.TenantID, q.OrganizationID, actor) {
		return View{}, ErrForbidden
	}
	if (op == ListTeams || exact) && out.Actor.Role != RoleOwner && out.Actor.Role != RoleAdministrator {
		return View{}, ErrForbidden
	}
	if err = s.authorize(bounded, actor, q.TenantID, q.OrganizationID, out.Organization.Version, op, r.CorrelationID); err != nil {
		return View{}, err
	}
	// Bounded callbacks confer no lease: re-read native session and membership
	// after policy, preserving the same organization epoch before disclosure.
	if _, current, e := s.authenticate(bounded, r.Authentication); e != nil || current != actor {
		if e != nil {
			return View{}, e
		}
		return View{}, ErrForbidden
	}
	fresh, e := s.repository.Read(bounded, q)
	if e != nil {
		return View{}, publicError(bounded, e)
	}
	if !validView(fresh, q.TenantID, q.OrganizationID, actor) || fresh.Organization.Version != out.Organization.Version || fresh.Actor != out.Actor {
		return View{}, ErrForbidden
	}
	if exact && (!validTeam(fresh.Team, q.TenantID, q.OrganizationID) || fresh.Team.ID != r.TeamID) {
		return View{}, ErrForbidden
	}
	if len(fresh.Teams) > int(r.Limit) || len(fresh.TeamMembers) > int(r.Limit) {
		return View{}, ErrUnavailable
	}
	for i, t := range fresh.Teams {
		if !validTeam(t, q.TenantID, q.OrganizationID) || string(t.ID) <= r.Cursor || i > 0 && fresh.Teams[i-1].ID >= t.ID {
			return View{}, ErrUnavailable
		}
	}
	for i, m := range fresh.TeamMembers {
		if !m.Active || m.TeamID != r.TeamID || m.OrganizationID != r.OrganizationID || m.TenantID != q.TenantID || m.Version == 0 || m.OrganizationMemberVersion == 0 || !safeID(string(m.UserID)) || string(m.UserID) <= r.Cursor || i > 0 && fresh.TeamMembers[i-1].UserID >= m.UserID {
			return View{}, ErrUnavailable
		}
	}
	if fresh.NextTeamCursor != "" {
		if len(fresh.Teams) == int(r.Limit) {
			if fresh.NextTeamCursor != string(fresh.Teams[len(fresh.Teams)-1].ID) {
				return View{}, ErrUnavailable
			}
		} else if len(fresh.TeamMembers) == int(r.Limit) {
			if fresh.NextTeamCursor != string(fresh.TeamMembers[len(fresh.TeamMembers)-1].UserID) {
				return View{}, ErrUnavailable
			}
		} else {
			return View{}, ErrUnavailable
		}
	}
	if err = bounded.Err(); err != nil {
		return View{}, err
	}
	return fresh, nil
}
