package postgres

import (
	"context"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

func (s *Service) activeRecoverySession(ctx context.Context, a organization.Authentication, b identity.CommandBinding) (session.GetResult, session.SessionSpec, error) {
	token, err := session.ParseToken(a.Bearer.Token())
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, organization.ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, organization.ErrForbidden
	}
	current, err := s.config.Sessions.Get(ctx, session.GetRequest{TenantID: a.TenantID, Credential: credential})
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, storageError(ctx, err)
	}
	spec, err := current.Session.Bindings()
	if err != nil || current.ValidateAt(s.config.Core.Clock.Now()) != nil || spec.SessionID != b.RecordID || spec.TenantID != b.TenantID || spec.UserID != b.UserID || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "password" || spec.Authentication.Proof.Assurance != authentication.AssuranceSingleFactor {
		return session.GetResult{}, session.SessionSpec{}, organization.ErrForbidden
	}
	if _, err := current.Session.CSRFState().Bindings(); err == nil {
		return session.GetResult{}, session.SessionSpec{}, organization.ErrForbidden
	}
	if _, _, _, err := sessionpg.OriginalOrganizationPasswordSessionAdmission(s.participant.config.Profile, current.Session, b); err != nil {
		return session.GetResult{}, session.SessionSpec{}, organization.ErrForbidden
	}
	return current, spec, nil
}

func (s *Service) revalidateActiveRecovery(ctx context.Context, a organization.Authentication, b identity.CommandBinding, observed session.GetResult, original session.SessionSpec) error {
	current, spec, err := s.activeRecoverySession(ctx, a, b)
	if err != nil {
		return err
	}
	old, _ := original.Authority.Bindings()
	now, _ := spec.Authority.Bindings()
	// Metadata-only history access is not a new lease. Current reads may shorten
	// freshness, but cannot change the original exact session or renew its fence.
	if original.Version != spec.Version || original.FamilyID != spec.FamilyID || original.FamilyVersion != spec.FamilyVersion || old != now || observed.ValidateAt(s.config.Core.Clock.Now()) != nil || current.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.ErrForbidden
	}
	return ctx.Err()
}

func (s *Service) recoverActiveOrganization(ctx context.Context, a organization.Authentication, b identity.CommandBinding) (out organization.StoreResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = organization.StoreResult{}, organization.ErrUnavailable
		}
	}()
	if s.participant == nil || s.participant.selection == nil || s.core == nil || b.ValidateFor(organization.ActiveSet.Descriptor()) != nil || b.UserID != identity.UserID(b.ActorID) || b.ActorKind != authorization.SubjectUser || b.TenantID != a.TenantID || b.PolicyID != s.config.Core.PolicyID || b.PolicyVersion != s.config.Core.PolicyVersion {
		return out, organization.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	observed, spec, err := s.activeRecoverySession(ctx, a, b)
	if err != nil {
		return out, err
	}
	// The historical result contains only command/session correlation, no target
	// organization. Authorize its exact self-session disclosure, not a mutation
	// against a former target or an arbitrary current organization.
	decision, err := s.config.Authorization.Decide(ctx, authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Core.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(organization.ActiveSet), Resource: authorization.Resource{Type: "session", ID: authorization.ResourceID(b.RecordID)}, Tenant: authorization.TenantID(b.TenantID), Environment: authorization.Environment{Time: s.config.Core.Clock.Now()}}})
	if err != nil {
		return out, storageError(ctx, err)
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(s.config.Core.PolicyVersion) {
		return out, organization.ErrForbidden
	}
	if err := s.revalidateActiveRecovery(ctx, a, b, observed, spec); err != nil {
		return out, err
	}
	query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Core.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}, Tenant: authorization.TenantID(b.TenantID), Environment: authorization.Environment{Time: s.config.Core.Clock.Now()}}}
	var receipt identity.CommandResult
	if s.participant.operationRestore != nil {
		feature := kernel.FeatureRegistration{Contributor: s.participant.Descriptor(), Operation: organization.ActiveSet.Descriptor()}
		receipt, err = s.config.Coordinator.RecoverPreparedFeatureCommand(ctx, query, caller, feature, s.participant)
	} else {
		receipt, err = s.config.Coordinator.RecoverFeatureCommand(ctx, query, caller)
	}
	if fence := s.revalidateActiveRecovery(ctx, a, b, observed, spec); fence != nil {
		return out, fence
	}
	if receipt.Outcome != identity.CommitOutcomeInvalid && receipt.Binding != b {
		return out, organization.ErrUnavailable
	}
	return mutationResult(b, receipt), operationError(ctx, err)
}
