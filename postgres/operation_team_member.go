package postgres

import (
	"context"
	"errors"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

// AddTeamMember admits an exact organization admission and team binding through
// the existing native team owner. IDs and all four expected versions are key
// intent; CorrelationID is diagnostic only. Matching retries recover the original
// receipt under current manager/session authority, never prepare or execute again
// after an unknown outcome. Network is the trusted canonical full client IP.
func (s *OperationService) AddTeamMember(ctx context.Context, r organization.AddTeamMemberOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	fields := []identity.FeatureField{text("id", string(r.OrganizationID)), text("team-id", string(r.TeamID)), text("target", string(r.UserID)), number("version", r.OrganizationVersion), number("team-version", r.TeamVersion), number("organization-member-version", r.OrganizationMemberVersion), number("team-member-version", r.MembershipVersion)}
	return s.state().keyed(ctx, r.Authentication, organization.AddTeamMember, r.IdempotencyKey, fields, network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		return service.core.PrepareAddTeamMember(ctx, organization.TeamMemberRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, TeamID: r.TeamID, UserID: r.UserID, OrganizationVersion: r.OrganizationVersion, TeamVersion: r.TeamVersion, OrganizationMemberVersion: r.OrganizationMemberVersion, MembershipVersion: r.MembershipVersion, CorrelationID: r.CorrelationID})
	})
}

// RemoveTeamMember naturally repeats an exact binding removal without a caller
// command or key. Install TeamMemberOperationLookupMigrationSource first. Only
// actual correlated effects and their original native receipts establish prior
// success; absent or legacy rows never do. A newer organization admission or team
// binding conflicts. Unknown execution returns immediately, without another
// attempt; retain its binding for RecoverOperation. Network is a trusted IP.
func (s *OperationService) RemoveTeamMember(ctx context.Context, r organization.RemoveTeamMemberOperationRequest, network string) (out organization.StoreResult, err error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil || !operationNetwork(network) {
		return out, organization.ErrInvalidInput
	}
	state := s.state()
	ctx, cancel := context.WithTimeout(ctx, state.source.config.Core.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = organization.StoreResult{}, organization.ErrUnavailable
		}
	}()
	actor, err := state.actor(ctx, r.Authentication)
	if err != nil {
		return out, err
	}
	if original, found, err := state.teamMemberRemovalOutcome(ctx, r, actor); err != nil || found {
		return original, err
	}
	service, err := state.compose(nil)
	if err != nil {
		return out, err
	}
	// The immutable per-invocation participant alone selects the optional
	// correlated INSERT. Raw explicit team execution retains its original schema.
	service.participant.naturalTeamRemove = true
	id, err := identity.NewCommandID()
	if err != nil {
		return out, organization.ErrUnavailable
	}
	prepared, err := service.PrepareRemoveTeamMember(ctx, organization.TeamMemberRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, TeamID: r.TeamID, UserID: r.UserID, OrganizationVersion: r.OrganizationVersion, TeamVersion: r.TeamVersion, OrganizationMemberVersion: r.OrganizationMemberVersion, MembershipVersion: r.MembershipVersion, CorrelationID: r.CorrelationID}, network)
	if err == nil {
		out, err = service.Execute(ctx, prepared)
	}
	// A competing exact request can commit after the first empty lookup. Resolve
	// only its actual existing effect; unknown outcomes never enter this path.
	if errors.Is(err, organization.ErrConflict) || errors.Is(err, organization.ErrForbidden) {
		if original, found, lookupErr := state.teamMemberRemovalOutcome(ctx, r, actor); lookupErr != nil || found {
			return original, lookupErr
		}
	}
	return out, err
}

// ListMyTeams reads current exact-admission bindings from the existing native
// primary. It creates no cache, authority projection or request-key admission.
func (s *OperationService) ListMyTeams(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if s == nil || s.state == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.state().source.ListMyTeams(ctx, r)
}

// ListTeamMembers preserves the native bounded cursor and current manager or
// exact team-member read authority, without mutating session activity.
func (s *OperationService) ListTeamMembers(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if s == nil || s.state == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.state().source.ListTeamMembers(ctx, r)
}

// The optional partial unique index bounds this exact original organization
// epoch probe. Legacy NULL selectors cannot reconstruct original team intent.
const teamMemberRemovalOperationLookupSQL = `SELECT command_id,remove_team_id,remove_team_version::text,remove_org_member_version::text,remove_membership_version::text,actor_id,user_id
FROM organization.command_effects
WHERE tenant_id=$1 AND organization_id=$2 AND before_version=$3::numeric
AND operation='identity.organization.team.member-remove' AND remove_team_id IS NOT NULL
LIMIT 2`

func (s *operationServiceState) teamMemberRemovalOutcome(ctx context.Context, r organization.RemoveTeamMemberOperationRequest, actor identity.UserID) (organization.StoreResult, bool, error) {
	if err := s.teamMemberRemovalAdmission(ctx, r, actor); err != nil {
		return organization.StoreResult{}, false, err
	}
	rows, err := s.source.participant.repository.pool.Raw().Query(ctx, teamMemberRemovalOperationLookupSQL, string(r.Authentication.TenantID), string(r.OrganizationID), strconv.FormatUint(r.OrganizationVersion, 10))
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	var id identity.CommandID
	var team, teamVersion, admissionVersion, bindingVersion, originalActor, target string
	count := 0
	for rows.Next() {
		count++
		if rows.Scan(&id, &team, &teamVersion, &admissionVersion, &bindingVersion, &originalActor, &target) != nil || count > 1 {
			rows.Close()
			return organization.StoreResult{}, false, organization.ErrUnavailable
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	if count == 0 {
		return organization.StoreResult{}, false, nil
	}
	if _, err := identity.ParseCommandID(string(id)); err != nil {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	if team != string(r.TeamID) || teamVersion != strconv.FormatUint(r.TeamVersion, 10) || admissionVersion != strconv.FormatUint(r.OrganizationMemberVersion, 10) || bindingVersion != strconv.FormatUint(r.MembershipVersion, 10) || originalActor != string(actor) || target != string(r.UserID) {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	service, err := s.compose(nil)
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	service.participant.naturalTeamRemove = true
	query := identity.RecoveryQuery{CommandID: id, TenantID: r.Authentication.TenantID, UserID: r.UserID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, OperationID: string(organization.RemoveTeamMember), RecordID: string(r.OrganizationID)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Coordinator.QueryPolicy.PolicyVersion), CorrelationID: r.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(r.Authentication.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: authorization.Action(organization.RemoveTeamMember), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(r.UserID)}}}
	original, err := service.config.Coordinator.QueryCommand(ctx, query, caller)
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	if original.Validate() != nil || original.Binding.ValidateFor(organization.RemoveTeamMember.Descriptor()) != nil || original.Feature == nil || *original.Feature != organization.RemoveTeamMember.Descriptor() {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	out, err := service.Recover(ctx, r.Authentication, Recovery{Binding: original.Binding})
	if err != nil {
		return out, true, operationError(ctx, err)
	}
	if out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature == nil || out.Receipt.Feature.BeforeVersion != r.OrganizationVersion || out.Receipt.Feature.AfterVersion != r.OrganizationVersion+1 {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	// Check the current exact admission after all disclosure callbacks. Historical
	// recovery is not permission to reach a newer binding or readmitted subject.
	current, err := s.source.participant.repository.Read(ctx, organization.Query{Operation: organization.RemoveTeamMember, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, TeamID: r.TeamID, TargetID: r.UserID})
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	if !current.Target.Active || current.Target.Version != r.OrganizationMemberVersion || current.TargetUser.Status != identity.StatusActive || current.TeamMember.Active || current.TeamMember.Version != r.MembershipVersion+1 || current.TeamMember.OrganizationMemberVersion != r.OrganizationMemberVersion || current.Team.Version < r.TeamVersion+1 {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	return out, true, nil
}

// Natural lookup can classify changed selectors before a command is identified.
// Authenticate its actual session, authorize the actual team-write operation and
// fence the same original observation around that callback before classification.
// This binding contains decision scope only: no command ID, claim or execution
// authority is invented, persisted, queried or exported.
func (s *operationServiceState) teamMemberRemovalAdmission(ctx context.Context, r organization.RemoveTeamMemberOperationRequest, actor identity.UserID) error {
	token, err := session.ParseToken(r.Authentication.Bearer.Token())
	if err != nil {
		return organization.ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return organization.ErrForbidden
	}
	observed, err := s.source.config.Sessions.Get(ctx, session.GetRequest{TenantID: r.Authentication.TenantID, Credential: credential})
	if err != nil {
		return operationError(ctx, err)
	}
	if observed.ValidateAt(s.source.config.Core.Clock.Now()) != nil {
		return organization.ErrForbidden
	}
	bound, err := observed.Session.Bindings()
	if err != nil || bound.TenantID != r.Authentication.TenantID || bound.UserID != actor {
		return organization.ErrForbidden
	}
	b := identity.CommandBinding{TenantID: r.Authentication.TenantID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, UserID: r.UserID, OperationID: string(organization.RemoveTeamMember), RecordID: string(r.OrganizationID), CorrelationID: r.CorrelationID}
	actorBinding := b
	actorBinding.UserID = actor
	if _, _, _, err := sessionpg.OriginalSessionAdmission(s.source.participant.config.Profile, observed.Session, actorBinding); err != nil {
		return organization.ErrForbidden
	}
	view, err := s.source.participant.repository.Read(ctx, organization.Query{Operation: organization.Get, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID})
	if err != nil {
		return err
	}
	admitted := &recoveryInput{binding: b, observed: observed, credential: credential, organization: view.Organization, member: view.Actor}
	if err := s.source.revalidateRecovery(ctx, admitted); err != nil {
		return err
	}
	if err := s.source.authorizeUpdateRecovery(ctx, b, view); err != nil {
		return err
	}
	return s.source.revalidateRecovery(ctx, admitted)
}

func (p *Contributor) teamMemberRemovalEffect(ctx context.Context, w kernel.Work, c nativeCommand, fingerprint []byte) (identity.FeatureReceipt, error) {
	b := c.spec.Binding
	_, err := w.Exec(ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version,remove_team_id,remove_team_version,remove_org_member_version,remove_membership_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10,$11::numeric,$12::numeric,$13::numeric)`, string(b.CommandID), string(b.TenantID), string(c.org.ID), string(b.UserID), string(b.ActorID), b.OperationID, fingerprint, strconv.FormatUint(c.org.Version, 10), strconv.FormatUint(c.org.Version+1, 10), string(c.team.ID), strconv.FormatUint(c.team.Version, 10), strconv.FormatUint(c.target.Version, 10), strconv.FormatUint(c.teamMember.Version, 10))
	return identity.FeatureReceipt{Operation: c.spec.Operation, BeforeVersion: c.org.Version, AfterVersion: c.org.Version + 1}, err
}
