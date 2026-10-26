package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

func isDynamicRoleCRUDOperation(op organization.Operation) bool {
	return op == organization.CreateDynamicRole || op == organization.UpdateDynamicRole || op == organization.DeleteDynamicRole
}

// CreateDynamicRole admits one original key and chosen role identity through the
// existing native catalog/role owner. Ordered statements are frozen before any
// callbacks or IO. Matching retries recover only the original outcome under
// current role-write/session/query authority, never reexecute an unknown result.
// Network is the transport's trusted canonical full client IP.
func (s *OperationService) CreateDynamicRole(ctx context.Context, r organization.CreateDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || len(r.Statements) > 64 {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	r.Statements = slices.Clone(r.Statements)
	if r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	wire, err := json.Marshal(r.Statements)
	if err != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	fields := []identity.FeatureField{text("id", string(r.OrganizationID)), text("role-id", string(r.RoleID)), number("version", r.OrganizationVersion), text("name", r.Name), text("statements", string(wire))}
	return s.state().keyed(ctx, r.Authentication, organization.CreateDynamicRole, r.IdempotencyKey, fields, network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		return service.core.PrepareCreateDynamicRole(ctx, organization.DynamicRoleRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: r.OrganizationVersion, Name: r.Name, Statements: r.Statements, CorrelationID: r.CorrelationID})
	})
}

// UpdateDynamicRole replaces the complete ordered name/statements at exact
// organization/role epochs through the real native owner. Borrowed statements
// are frozen before callbacks; the immutable catalog remains native policy.
// Original-key retries recover, never renew authority or execute again after an
// unknown result. Network is the trusted canonical full client IP.
func (s *OperationService) UpdateDynamicRole(ctx context.Context, r organization.UpdateDynamicRoleOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || len(r.Statements) > 64 {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	r.Statements = slices.Clone(r.Statements)
	if r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	wire, err := json.Marshal(r.Statements)
	if err != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	fields := []identity.FeatureField{text("id", string(r.OrganizationID)), text("role-id", string(r.RoleID)), number("version", r.OrganizationVersion), number("role-version", r.RoleVersion), text("name", r.Name), text("statements", string(wire))}
	return s.state().keyed(ctx, r.Authentication, organization.UpdateDynamicRole, r.IdempotencyKey, fields, network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		return service.core.PrepareUpdateDynamicRole(ctx, organization.DynamicRoleRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: r.OrganizationVersion, RoleVersion: r.RoleVersion, Name: r.Name, Statements: r.Statements, CorrelationID: r.CorrelationID})
	})
}

// GetDynamicRole delegates exact current role/binding discovery to the existing
// native reader, including role-read and final session/policy fences.
func (s *OperationService) GetDynamicRole(ctx context.Context, r organization.DynamicRoleReadRequest) (organization.View, error) {
	if s == nil || s.state == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.state().source.GetDynamicRole(ctx, r)
}

// ListDynamicRoles delegates the existing current custom-role keyset page;
// static roles remain the closed Role constants, not fabricated custom rows.
func (s *OperationService) ListDynamicRoles(ctx context.Context, r organization.DynamicRoleReadRequest) (organization.View, error) {
	if s == nil || s.state == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.state().source.ListDynamicRoles(ctx, r)
}

// CheckPermission delegates actual current direct/team statement evaluation and
// deny precedence. A returned allow is not a lease; exact policy epochs and all
// native current session/membership fences remain mandatory on every check.
func (s *OperationService) CheckPermission(ctx context.Context, r organization.PermissionCheckRequest) (authorization.Decision, error) {
	if s == nil || s.state == nil {
		return authorization.Decision{}, organization.ErrInvalidInput
	}
	return s.state().source.CheckPermission(ctx, r)
}

// DeleteDynamicRole naturally repeats exact-version terminal retirement without
// a key or caller command. Install DynamicRoleDeleteOperationLookupMigrationSource
// before selecting it. Only matching original effect correlation and the real
// native receipt prove success; terminal state alone never does. Unknown results
// return immediately: retain their binding for RecoverOperation. Current actual
// role-write/session/query authority remains required, even for changed-selector
// classification. Network is the trusted canonical full client IP.
func (s *OperationService) DeleteDynamicRole(ctx context.Context, r organization.DeleteDynamicRoleOperationRequest, network string) (out organization.StoreResult, err error) {
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
	if original, found, err := state.dynamicRoleDeleteOperationOutcome(ctx, r, actor); err != nil || found {
		return original, err
	}
	service, err := state.compose(nil)
	if err != nil {
		return out, err
	}
	service.participant.naturalDynamicRoleDelete = true
	id, err := identity.NewCommandID()
	if err != nil {
		return out, organization.ErrUnavailable
	}
	p, err := service.PrepareDeleteDynamicRole(ctx, organization.DynamicRoleRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: r.OrganizationVersion, RoleVersion: r.RoleVersion, CorrelationID: r.CorrelationID}, network)
	if err == nil {
		out, err = service.Execute(ctx, p)
	}
	if errors.Is(err, organization.ErrConflict) || errors.Is(err, organization.ErrForbidden) {
		if original, found, lookupErr := state.dynamicRoleDeleteOperationOutcome(ctx, r, actor); lookupErr != nil || found {
			return original, lookupErr
		}
	}
	return out, err
}

// A correlated terminal effect identifies at most one original role deletion at
// an organization epoch. Legacy effects cannot establish its missing selectors.
const dynamicRoleDeleteOperationLookupSQL = `SELECT command_id,delete_role_id,delete_role_version::text,actor_id,user_id
FROM organization.command_effects
WHERE tenant_id=$1 AND organization_id=$2 AND before_version=$3::numeric
AND operation='identity.organization.role.delete' AND delete_role_id IS NOT NULL
LIMIT 2`

func (s *operationServiceState) dynamicRoleDeleteOperationOutcome(ctx context.Context, r organization.DeleteDynamicRoleOperationRequest, actor identity.UserID) (organization.StoreResult, bool, error) {
	admitted, err := s.dynamicRoleDeleteOperationAdmission(ctx, r, actor)
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	rows, err := s.source.participant.repository.pool.Raw().Query(ctx, dynamicRoleDeleteOperationLookupSQL, string(r.Authentication.TenantID), string(r.OrganizationID), strconv.FormatUint(r.OrganizationVersion, 10))
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	var id identity.CommandID
	var role, version, originalActor, user string
	count := 0
	for rows.Next() {
		count++
		if rows.Scan(&id, &role, &version, &originalActor, &user) != nil || count > 1 {
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
	service.participant.naturalDynamicRoleDelete = true
	query := identity.RecoveryQuery{CommandID: id, TenantID: r.Authentication.TenantID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, UserID: identity.UserID(user), OperationID: string(organization.DeleteDynamicRole), RecordID: string(r.OrganizationID)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Coordinator.QueryPolicy.PolicyVersion), CorrelationID: r.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(r.Authentication.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: authorization.Action(organization.DeleteDynamicRole), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	original, err := service.config.Coordinator.QueryCommand(ctx, query, caller)
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	// Query callbacks may withdraw the original native observation; do not
	// classify its history under renewed or merely pre-query authority.
	if err := s.source.revalidateRecovery(ctx, admitted); err != nil {
		return organization.StoreResult{}, false, err
	}
	if original.Validate() != nil || original.Binding.ValidateFor(organization.DeleteDynamicRole.Descriptor()) != nil || original.Feature == nil || *original.Feature != organization.DeleteDynamicRole.Descriptor() {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	if role != string(r.RoleID) || version != strconv.FormatUint(r.RoleVersion, 10) || originalActor != string(actor) || user != string(actor) {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	out, err := service.Recover(ctx, r.Authentication, Recovery{Binding: original.Binding})
	if err != nil {
		return out, true, operationError(ctx, err)
	}
	if out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature == nil || out.Receipt.Feature.BeforeVersion != r.OrganizationVersion || out.Receipt.Feature.AfterVersion != r.OrganizationVersion+1 {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	var retiredVersion, state string
	err = s.source.participant.repository.pool.Raw().QueryRow(ctx, `SELECT version::text,state FROM organization.custom_roles WHERE tenant_id=$1 AND organization_id=$2 AND role_id=$3`, string(r.Authentication.TenantID), string(r.OrganizationID), string(r.RoleID)).Scan(&retiredVersion, &state)
	// Terminal IO can outlive admission. Fence the same original observation
	// after it, keeping current native authority last without renewing validity.
	if admissionErr := s.source.revalidateRecovery(ctx, admitted); admissionErr != nil {
		return organization.StoreResult{}, false, admissionErr
	}
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	if state != "deleted" || retiredVersion != strconv.FormatUint(r.RoleVersion+1, 10) {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	return out, true, nil
}

// Admission metadata uses the actual session and owning native current-action
// checks before even classifying changed selectors. It is not a forged command
// or authorization grant; normal original query/recovery fences still follow.
func (s *operationServiceState) dynamicRoleDeleteOperationAdmission(ctx context.Context, r organization.DeleteDynamicRoleOperationRequest, actor identity.UserID) (*recoveryInput, error) {
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
	b := identity.CommandBinding{TenantID: r.Authentication.TenantID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, UserID: actor, OperationID: string(organization.DeleteDynamicRole), RecordID: string(r.OrganizationID), CorrelationID: r.CorrelationID}
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

func (p *Contributor) dynamicRoleDeleteOperationEffect(ctx context.Context, w kernel.Work, c nativeCommand, fingerprint []byte) (identity.FeatureReceipt, error) {
	b := c.spec.Binding
	_, err := w.Exec(ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version,delete_role_id,delete_role_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10,$11::numeric)`, string(b.CommandID), string(b.TenantID), string(c.org.ID), string(b.UserID), string(b.ActorID), b.OperationID, fingerprint, strconv.FormatUint(c.org.Version, 10), strconv.FormatUint(c.org.Version+1, 10), string(c.dynamicRole.ID), strconv.FormatUint(c.dynamicRole.Version, 10))
	return identity.FeatureReceipt{Operation: c.spec.Operation, BeforeVersion: c.org.Version, AfterVersion: c.org.Version + 1}, err
}
