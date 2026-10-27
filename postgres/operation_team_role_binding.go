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

// AssignTeamDynamicRole admits one original keyed team-targeted assignment
// through the existing native role/team owner. All identities and four epochs
// are immutable intent; no human target is supplied or impersonated. Matching
// retries disclose the original result under current native manager/session,
// role-action and query authority, never renew a grant or execute an unknown
// result. Network is the transport's trusted canonical full client IP.
func (s *OperationService) AssignTeamDynamicRole(ctx context.Context, r organization.AssignTeamDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	// The team selector distinguishes this intent from direct assignment even
	// though both deliberately retain the existing role.assign descriptor.
	fields := []identity.FeatureField{text("id", string(r.OrganizationID)), text("role-id", string(r.RoleID)), text("team-id", string(r.TeamID)), number("version", r.OrganizationVersion), number("role-version", r.RoleVersion), number("team-version", r.TeamVersion), number("binding-version", r.BindingVersion)}
	return s.state().keyed(ctx, r.Authentication, organization.AssignDynamicRole, r.IdempotencyKey, fields, network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		return service.core.PrepareAssignTeamDynamicRole(ctx, organization.TeamRoleBindingRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion, RoleVersion: r.RoleVersion, TeamVersion: r.TeamVersion, BindingVersion: r.BindingVersion, CorrelationID: r.CorrelationID})
	})
}

// RevokeTeamDynamicRole naturally repeats one exact team-role revocation without
// a caller command or key. Install TeamRoleBindingRevokeOperationLookupMigrationSource
// before selection. Only original correlated effects and the actual native
// receipt establish success, never missing bindings or tombstones alone. Current
// native manager/session, actual role-action and original query authority apply
// before historical classification and after final binding IO. New assignments
// and terminal teams cannot be reached by old selectors. Unknown execution is
// never replayed; retain its original binding for explicit RecoverOperation.
// Network is the trusted canonical full client IP.
func (s *OperationService) RevokeTeamDynamicRole(ctx context.Context, r organization.RevokeTeamDynamicRoleOperationRequest, network string) (out organization.StoreResult, err error) {
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
	if original, found, err := state.teamRoleBindingRevokeOutcome(ctx, r, actor); err != nil || found {
		return original, err
	}
	service, err := state.compose(nil)
	if err != nil {
		return out, err
	}
	service.participant.naturalTeamRoleRevoke = true
	id, err := identity.NewCommandID()
	if err != nil {
		return out, organization.ErrUnavailable
	}
	p, err := service.PrepareRevokeTeamDynamicRole(ctx, organization.TeamRoleBindingRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion, RoleVersion: r.RoleVersion, TeamVersion: r.TeamVersion, BindingVersion: r.BindingVersion, CorrelationID: r.CorrelationID}, network)
	if err == nil {
		out, err = service.Execute(ctx, p)
	}
	if errors.Is(err, organization.ErrConflict) || errors.Is(err, organization.ErrForbidden) {
		if original, found, lookupErr := state.teamRoleBindingRevokeOutcome(ctx, r, actor); lookupErr != nil || found {
			return original, lookupErr
		}
	}
	return out, err
}

// Team-only nullable selectors cannot alias the existing direct-revoke lookup.
// One aggregate epoch admits at most one correlated original in this profile.
const teamRoleBindingRevokeOperationLookupSQL = `SELECT command_id,revoke_team_role_id,revoke_team_role_version::text,revoke_team_id,revoke_team_version::text,revoke_team_binding_version::text,actor_id,user_id
FROM organization.command_effects
WHERE tenant_id=$1 AND organization_id=$2 AND before_version=$3::numeric
AND operation='identity.organization.role.revoke' AND revoke_team_id IS NOT NULL
LIMIT 2`

func (s *operationServiceState) teamRoleBindingRevokeOutcome(ctx context.Context, r organization.RevokeTeamDynamicRoleOperationRequest, actor identity.UserID) (organization.StoreResult, bool, error) {
	admitted, err := s.teamRoleBindingRevokeAdmission(ctx, r, actor)
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	rows, err := s.source.participant.repository.pool.Raw().Query(ctx, teamRoleBindingRevokeOperationLookupSQL, string(r.Authentication.TenantID), string(r.OrganizationID), strconv.FormatUint(r.OrganizationVersion, 10))
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	var id identity.CommandID
	var role, roleVersion, team, teamVersion, bindingVersion, originalActor, user string
	count := 0
	for rows.Next() {
		count++
		if rows.Scan(&id, &role, &roleVersion, &team, &teamVersion, &bindingVersion, &originalActor, &user) != nil || count > 1 {
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
	service, err := s.compose(nil)
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	service.participant.naturalTeamRoleRevoke = true
	// The stored user is the original human actor, never the team identity.
	// Current callers cannot impersonate that principal to obtain history.
	query := identity.RecoveryQuery{CommandID: id, TenantID: r.Authentication.TenantID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, UserID: identity.UserID(user), OperationID: string(organization.RevokeDynamicRole), RecordID: string(r.OrganizationID)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Coordinator.QueryPolicy.PolicyVersion), CorrelationID: r.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(r.Authentication.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: authorization.Action(organization.RevokeDynamicRole), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	original, err := service.config.Coordinator.QueryCommand(ctx, query, caller)
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	if err := s.source.revalidateRecovery(ctx, admitted); err != nil {
		return organization.StoreResult{}, false, err
	}
	if original.Validate() != nil || original.Binding.ValidateFor(organization.RevokeDynamicRole.Descriptor()) != nil || original.Feature == nil || *original.Feature != organization.RevokeDynamicRole.Descriptor() {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	if role != string(r.RoleID) || roleVersion != strconv.FormatUint(r.RoleVersion, 10) || team != string(r.TeamID) || teamVersion != strconv.FormatUint(r.TeamVersion, 10) || bindingVersion != strconv.FormatUint(r.BindingVersion, 10) || originalActor != string(actor) || user != string(actor) {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	out, err := service.Recover(ctx, r.Authentication, Recovery{Binding: original.Binding})
	if err != nil {
		return out, true, operationError(ctx, err)
	}
	if out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature == nil || out.Receipt.Feature.BeforeVersion != r.OrganizationVersion || out.Receipt.Feature.AfterVersion != r.OrganizationVersion+1 {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	current, err := s.source.participant.repository.Read(ctx, organization.Query{Operation: organization.RevokeDynamicRole, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, DynamicRoleID: r.RoleID, TeamID: r.TeamID})
	// Keep the same original native observation last, after all fallible team
	// and binding IO. A new observation would improperly renew its validity.
	if admissionErr := s.source.revalidateRecovery(ctx, admitted); admissionErr != nil {
		return organization.StoreResult{}, false, admissionErr
	}
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	if current.TeamRoleBinding.Active || current.TeamRoleBinding.Version != r.BindingVersion+1 || current.Team.Version < r.TeamVersion+1 || current.DynamicRole.Version < r.RoleVersion {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	return out, true, nil
}

// Admission metadata uses the real current human and native membership snapshot;
// it allocates no command, authority, grant or renewed observation.
func (s *operationServiceState) teamRoleBindingRevokeAdmission(ctx context.Context, r organization.RevokeTeamDynamicRoleOperationRequest, actor identity.UserID) (*recoveryInput, error) {
	token, err := session.ParseToken(r.Authentication.Bearer.Token())
	if err != nil {
		return nil, organization.ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return nil, organization.ErrForbidden
	}
	observed, err := s.source.config.Sessions.Get(ctx, session.GetRequest{TenantID: r.Authentication.TenantID, Credential: credential})
	if err != nil {
		return nil, operationError(ctx, err)
	}
	if observed.ValidateAt(s.source.config.Core.Clock.Now()) != nil {
		return nil, organization.ErrForbidden
	}
	bound, err := observed.Session.Bindings()
	if err != nil || bound.TenantID != r.Authentication.TenantID || bound.UserID != actor {
		return nil, organization.ErrForbidden
	}
	b := identity.CommandBinding{TenantID: r.Authentication.TenantID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, UserID: actor, OperationID: string(organization.RevokeDynamicRole), RecordID: string(r.OrganizationID), CorrelationID: r.CorrelationID}
	if _, _, _, err := sessionpg.OriginalSessionAdmission(s.source.participant.config.Profile, observed.Session, b); err != nil {
		return nil, organization.ErrForbidden
	}
	view, err := s.source.participant.repository.Read(ctx, organization.Query{Operation: organization.Get, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID})
	if err != nil {
		return nil, err
	}
	admitted := &recoveryInput{binding: b, observed: observed, credential: credential, organization: view.Organization, member: view.Actor}
	if err := s.source.revalidateRecovery(ctx, admitted); err != nil {
		return nil, err
	}
	if err := s.source.authorizeUpdateRecovery(ctx, b, view); err != nil {
		return nil, err
	}
	if err := s.source.revalidateRecovery(ctx, admitted); err != nil {
		return nil, err
	}
	return admitted, nil
}

func (p *Contributor) teamRoleBindingRevokeEffect(ctx context.Context, w kernel.Work, c nativeCommand, fingerprint []byte) (identity.FeatureReceipt, error) {
	b := c.spec.Binding
	_, err := w.Exec(ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version,revoke_team_role_id,revoke_team_role_version,revoke_team_id,revoke_team_version,revoke_team_binding_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10,$11::numeric,$12,$13::numeric,$14::numeric)`, string(b.CommandID), string(b.TenantID), string(c.org.ID), string(b.UserID), string(b.ActorID), b.OperationID, fingerprint, strconv.FormatUint(c.org.Version, 10), strconv.FormatUint(c.org.Version+1, 10), string(c.dynamicRole.ID), strconv.FormatUint(c.dynamicRole.Version, 10), string(c.team.ID), strconv.FormatUint(c.team.Version, 10), strconv.FormatUint(c.teamRoleBinding.Version, 10))
	return identity.FeatureReceipt{Operation: c.spec.Operation, BeforeVersion: c.org.Version, AfterVersion: c.org.Version + 1}, err
}
