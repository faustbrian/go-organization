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

// UpdateTeam replaces the bounded name at exact organization/team epochs using
// one original key and the existing native lifecycle owner. Matching retries
// recover only the original receipt under current team-write/session and query
// authority, never execute again or renew original authority after an unknown
// outcome. Network is the transport's trusted canonical full client IP.
func (s *OperationService) UpdateTeam(ctx context.Context, r organization.UpdateTeamOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	fields := []identity.FeatureField{text("id", string(r.OrganizationID)), text("team-id", string(r.TeamID)), number("version", r.OrganizationVersion), number("team-version", r.TeamVersion), text("name", r.Name)}
	return s.state().keyed(ctx, r.Authentication, organization.UpdateTeam, r.IdempotencyKey, fields, network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		return service.core.PrepareUpdateTeam(ctx, organization.UpdateTeamRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion, TeamVersion: r.TeamVersion, Name: r.Name, CorrelationID: r.CorrelationID})
	})
}

// GetTeam delegates the existing exact manager-only team read. Team-read,
// current session/scoped authority and lifecycle enablement stay native-owned.
func (s *OperationService) GetTeam(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if s == nil || s.state == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.state().source.GetTeam(ctx, r)
}

// DeleteTeam naturally repeats terminal deletion at exact organization/team
// epochs without a client key or command. Install
// TeamDeleteOperationLookupMigrationSource before selecting this API. Only actual original effect
// correlation and native receipts establish prior success; absence/tombstones
// never do. Current team-write, session and query authorization still apply.
// Unknown execution returns immediately without another attempt; retain its
// binding for RecoverOperation. Network is the trusted canonical full client IP.
func (s *OperationService) DeleteTeam(ctx context.Context, r organization.DeleteTeamOperationRequest, network string) (out organization.StoreResult, err error) {
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
	if original, found, err := state.teamDeleteOperationOutcome(ctx, r, actor); err != nil || found {
		return original, err
	}
	service, err := state.compose(nil)
	if err != nil {
		return out, err
	}
	service.participant.naturalTeamDelete = true
	id, err := identity.NewCommandID()
	if err != nil {
		return out, organization.ErrUnavailable
	}
	p, err := service.PrepareDeleteTeam(ctx, organization.DeleteTeamRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion, TeamVersion: r.TeamVersion, CorrelationID: r.CorrelationID}, network)
	if err == nil {
		out, err = service.Execute(ctx, p)
	}
	if errors.Is(err, organization.ErrConflict) || errors.Is(err, organization.ErrForbidden) {
		if original, found, lookupErr := state.teamDeleteOperationOutcome(ctx, r, actor); lookupErr != nil || found {
			return original, lookupErr
		}
	}
	return out, err
}

// One correlated terminal effect can exist at an original organization epoch.
// Legacy effects lack original team selectors and cannot prove natural success.
const teamDeleteOperationLookupSQL = `SELECT command_id,delete_team_id,delete_team_version::text,actor_id,user_id
FROM organization.command_effects
WHERE tenant_id=$1 AND organization_id=$2 AND before_version=$3::numeric
AND operation='identity.organization.team.delete' AND delete_team_id IS NOT NULL
LIMIT 2`

func (s *operationServiceState) teamDeleteOperationOutcome(ctx context.Context, r organization.DeleteTeamOperationRequest, actor identity.UserID) (organization.StoreResult, bool, error) {
	admitted, err := s.teamDeleteOperationAdmission(ctx, r, actor)
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	rows, err := s.source.participant.repository.pool.Raw().Query(ctx, teamDeleteOperationLookupSQL, string(r.Authentication.TenantID), string(r.OrganizationID), strconv.FormatUint(r.OrganizationVersion, 10))
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	var id identity.CommandID
	var team, version, originalActor, user string
	count := 0
	for rows.Next() {
		count++
		if rows.Scan(&id, &team, &version, &originalActor, &user) != nil || count > 1 {
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
	service.participant.naturalTeamDelete = true
	query := identity.RecoveryQuery{CommandID: id, TenantID: r.Authentication.TenantID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, UserID: identity.UserID(user), OperationID: string(organization.DeleteTeam), RecordID: string(r.OrganizationID)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Coordinator.QueryPolicy.PolicyVersion), CorrelationID: r.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(r.Authentication.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: authorization.Action(organization.DeleteTeam), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	original, err := service.config.Coordinator.QueryCommand(ctx, query, caller)
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	// Query callbacks may withdraw the original native observation; do not
	// classify its history under renewed or merely pre-query authority.
	if err := s.source.revalidateRecovery(ctx, admitted); err != nil {
		return organization.StoreResult{}, false, err
	}
	if original.Validate() != nil || original.Binding.ValidateFor(organization.DeleteTeam.Descriptor()) != nil || original.Feature == nil || *original.Feature != organization.DeleteTeam.Descriptor() {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	if team != string(r.TeamID) || version != strconv.FormatUint(r.TeamVersion, 10) || originalActor != string(actor) || user != string(actor) {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	out, err := service.Recover(ctx, r.Authentication, Recovery{Binding: original.Binding})
	if err != nil {
		return out, true, operationError(ctx, err)
	}
	if out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature == nil || out.Receipt.Feature.BeforeVersion != r.OrganizationVersion || out.Receipt.Feature.AfterVersion != r.OrganizationVersion+1 {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	var retired string
	var live bool
	err = s.source.participant.repository.pool.Raw().QueryRow(ctx, `SELECT deleted_version::text,EXISTS(SELECT 1 FROM organization.teams t WHERE t.tenant_id=i.tenant_id AND t.organization_id=i.organization_id AND t.team_id=i.team_id) FROM organization.team_identities i WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3`, string(r.Authentication.TenantID), string(r.OrganizationID), string(r.TeamID)).Scan(&retired, &live)
	// Terminal IO can outlive admission. Fence the same original observation
	// after it, keeping current native authority last without renewing validity.
	if admissionErr := s.source.revalidateRecovery(ctx, admitted); admissionErr != nil {
		return organization.StoreResult{}, false, admissionErr
	}
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	if live || retired != strconv.FormatUint(r.TeamVersion+1, 10) {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	return out, true, nil
}

// This is admission metadata only, never an invented command or authority. Use
// the actual session owner and existing native revalidation/action owner before
// classifying even a changed selector, then retain the normal query fences.
func (s *operationServiceState) teamDeleteOperationAdmission(ctx context.Context, r organization.DeleteTeamOperationRequest, actor identity.UserID) (*recoveryInput, error) {
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
	if err != nil || bound.UserID != actor || bound.TenantID != r.Authentication.TenantID {
		return nil, organization.ErrForbidden
	}
	b := identity.CommandBinding{TenantID: r.Authentication.TenantID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, UserID: actor, OperationID: string(organization.DeleteTeam), RecordID: string(r.OrganizationID), CorrelationID: r.CorrelationID}
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

func (p *Contributor) teamDeleteOperationEffect(ctx context.Context, w kernel.Work, c nativeCommand, fingerprint []byte) (identity.FeatureReceipt, error) {
	b := c.spec.Binding
	_, err := w.Exec(ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version,delete_team_id,delete_team_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10,$11::numeric)`, string(b.CommandID), string(b.TenantID), string(c.org.ID), string(b.UserID), string(b.ActorID), b.OperationID, fingerprint, strconv.FormatUint(c.org.Version, 10), strconv.FormatUint(c.org.Version+1, 10), string(c.team.ID), strconv.FormatUint(c.team.Version, 10))
	return identity.FeatureReceipt{Operation: c.spec.Operation, BeforeVersion: c.org.Version, AfterVersion: c.org.Version + 1}, err
}
