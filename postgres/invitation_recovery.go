package postgres

import (
	"context"
	"errors"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

// InvitationRecovery is persistable safe correlation, never authority. Binding
// names the invitation; OrganizationID must match the original frozen send
// declaration or the accepting/cancelled invitation's durable owning record.
// It contains no session, proof, output ciphertext or renewable execution lease.
type InvitationRecovery struct {
	Binding        identity.CommandBinding
	OrganizationID organization.ID
}

// Recovery returns the original safe correlation before attempting execution.
func (p PreparedInvitation) Recovery() (InvitationRecovery, error) {
	if p.state == nil {
		return InvitationRecovery{}, organization.ErrInvalidInput
	}
	return InvitationRecovery{Binding: p.state.input.Binding, OrganizationID: p.state.input.Organization.ID}, nil
}

// Recover authenticates a current genuine session for the original actor and
// rechecks current organization/recipient policy before asking the sole native
// coordinator for historical metadata. Execution expiry is not query authority:
// expired invitations may be queried but never renewed, executed or redelivered.
// The safe handle works on a new service instance without original proof or
// PreparedInvitation. Missing durable organization correlation fails closed.
func (s *InvitationService) Recover(ctx context.Context, a organization.Authentication, recovery InvitationRecovery) (organization.StoreResult, error) {
	if s == nil || ctx == nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	b := recovery.Binding
	op := organization.Operation(b.OperationID)
	if (op != organization.InvitationSend && op != organization.InvitationAccept && op != organization.InvitationCancel && op != organization.InvitationReject && op != organization.InvitationExpire && op != organization.InvitationResend) || b.ValidateFor(op.Descriptor()) != nil || b.PolicyID != s.config.Core.PolicyID || b.PolicyVersion != s.config.Core.PolicyVersion || b.ActorKind != authorization.SubjectUser || !scope(string(recovery.OrganizationID)) {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	x := organization.CommandInput{Binding: b, Operation: op, Organization: organization.Organization{ID: recovery.OrganizationID}, Invitation: organization.InvitationInput{Record: organization.Invitation{ID: organization.ID(b.RecordID)}}}
	p := &invitationPhase{service: s, input: x}
	if err := p.compose(); err != nil {
		return organization.StoreResult{}, invitationPublicError(err)
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	if a.TenantID != b.TenantID {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	observed, credential, err := s.observeInvitationRecovery(bounded, a, b.ActorID)
	if err != nil {
		return organization.StoreResult{}, err
	}
	actor, _ := observed.Session.Bindings()
	var version uint64
	var cancellation *recoveryInput
	var rejection *organization.InvitationSnapshot
	query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	if x.Operation == organization.InvitationResend {
		// Unlike initial send, resend always starts from an immutable owning
		// invitation row. Do not extend send-origin framing or trust caller org.
		var org, recipient string
		if err = s.actor.repository.pool.Raw().QueryRow(bounded, `SELECT organization_id,recipient_user_id FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$2`, string(b.TenantID), b.RecordID).Scan(&org, &recipient); err != nil {
			return organization.StoreResult{}, storageError(bounded, err)
		}
		if org != string(recovery.OrganizationID) || recipient != string(b.UserID) {
			return organization.StoreResult{}, organization.ErrForbidden
		}
		v, e := s.core.Get(bounded, organization.ReadRequest{Authentication: a, OrganizationID: recovery.OrganizationID, CorrelationID: b.CorrelationID})
		if e != nil {
			return organization.StoreResult{}, e
		}
		if v.Actor.Role != organization.RoleOwner && v.Actor.Role != organization.RoleAdministrator {
			return organization.StoreResult{}, organization.ErrForbidden
		}
		version = v.Organization.Version
		binding := b
		binding.RecordID = string(v.Organization.ID)
		cancellation = &recoveryInput{binding: binding, observed: observed, credential: credential, organization: v.Organization, member: v.Actor}
	} else if x.Operation == organization.InvitationCancel || x.Operation == organization.InvitationExpire {
		if b.UserID != actor.UserID {
			return organization.StoreResult{}, organization.ErrForbidden
		}
		current, err := s.repository.ReadInvitation(bounded, organization.InvitationQuery{Operation: op, TenantID: b.TenantID, ActorID: actor.UserID, OrganizationID: x.Organization.ID, InvitationID: x.Invitation.Record.ID})
		if err != nil {
			return organization.StoreResult{}, err
		}
		if current.Actor.Role != organization.RoleOwner && current.Actor.Role != organization.RoleAdministrator {
			return organization.StoreResult{}, organization.ErrForbidden
		}
		version = current.Organization.Version
		binding := b
		binding.RecordID = string(current.Organization.ID)
		cancellation = &recoveryInput{binding: binding, observed: observed, credential: credential, organization: current.Organization, member: current.Actor}
	} else if x.Operation == organization.InvitationSend {
		// Acknowledged preparation precedes the domain row. The sole kernel's
		// immutable original declaration, never caller-supplied org correlation
		// or row absence, binds historical lookup to the owning organization.
		caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Core.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}, Environment: authorization.Environment{Time: s.config.Core.Clock.Now()}}}
		origin, record, queryErr := p.coordinator.QueryOrganizationInvitationOrigin(bounded, query, caller, p)
		if record.Binding == (identity.CommandBinding{}) {
			if queryErr != nil {
				return organization.StoreResult{}, invitationPublicError(queryErr)
			}
			return organization.StoreResult{}, organization.ErrUnavailable
		}
		if record.Validate() != nil || record.Binding != b || record.Feature == nil || *record.Feature != organization.InvitationSend.Descriptor() || !scope(origin.OrganizationID) || origin.OrganizationVersion == 0 {
			return organization.StoreResult{}, organization.ErrUnavailable
		}
		if origin.OrganizationID != string(recovery.OrganizationID) {
			return organization.StoreResult{}, organization.ErrForbidden
		}
		// A retained terminal classification can accompany valid historical
		// metadata. It is not a zero-record current-query policy denial.
		if queryErr != nil && record.Outcome != identity.CommitOutcomeNotCommitted {
			return organization.StoreResult{}, invitationPublicError(queryErr)
		}
		current, err := s.invitationSendRecoveryMember(bounded, a, b, x.Organization.ID, observed, credential)
		if err != nil {
			return organization.StoreResult{}, err
		}
		version = current.organization.Version
	} else {
		// Acceptance always selects an existing issued invitation. Retain its
		// owning row/recipient comparison independently of historical metadata.
		var owningOrganization, recipient string
		if err = s.actor.repository.pool.Raw().QueryRow(bounded, `SELECT organization_id,recipient_user_id FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$2`, string(b.TenantID), b.RecordID).Scan(&owningOrganization, &recipient); err != nil {
			return organization.StoreResult{}, storageError(bounded, err)
		}
		if owningOrganization != string(recovery.OrganizationID) || recipient != string(b.UserID) || b.UserID != actor.UserID {
			return organization.StoreResult{}, organization.ErrForbidden
		}
		// The accepting recipient need not be a member when a transaction rolled
		// back. Current verified-recipient identity remains independently owned.
		current, err := s.repository.ReadInvitation(bounded, organization.InvitationQuery{Operation: organization.InvitationAccept, TenantID: b.TenantID, ActorID: actor.UserID, RecipientUserID: actor.UserID, OrganizationID: x.Organization.ID, InvitationID: x.Invitation.Record.ID})
		if err != nil {
			return organization.StoreResult{}, err
		}
		version = current.Organization.Version
		if op == organization.InvitationReject {
			i := current.Record.Invitation
			if current.RecipientUser.ID != b.UserID || current.RecipientUser.Status != identity.StatusActive || current.RecipientIdentifier.ID != i.RecipientIdentifierID || current.RecipientIdentifier.Version != i.RecipientIdentifierVersion || !current.RecipientIdentifier.Verified {
				return organization.StoreResult{}, organization.ErrForbidden
			}
			rejection = &current
		}
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Core.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(x.Organization.ID), Attributes: authorization.Attributes{"organization.policy-version": authorization.StringValue(strconv.FormatUint(version, 10))}}, Environment: authorization.Environment{Time: s.config.Core.Clock.Now()}}}
	decision, err := s.config.Authorization.Decide(bounded, caller)
	if err != nil {
		return organization.StoreResult{}, organization.ErrUnavailable
	}
	if decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision || observed.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	// The kernel's recovery disclosure policy uses the exact identity user scope
	// independently of the organization policy decision above.
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
	receipt, err := p.coordinator.RecoverFeatureCommand(bounded, query, caller)
	if cancellation != nil {
		// Reuse the native membership owner's exact session/org/member/scoped
		// fence after both external callbacks; no renewed policy or observation.
		owner := Service{participant: s.actor, config: ServiceConfig{Core: s.config.Core, Sessions: s.config.Sessions}}
		if e := owner.revalidateRecovery(bounded, cancellation); e != nil {
			return organization.StoreResult{}, e
		}
	}
	if rejection != nil {
		// Both disclosure policy callbacks may withdraw the original recipient
		// session/identifier or organization. Reuse the native session fence,
		// without inventing membership for a recipient who never joined.
		owner := Service{participant: s.actor, config: ServiceConfig{Core: s.config.Core, Sessions: s.config.Sessions}}
		if e := owner.revalidateRecovery(bounded, &recoveryInput{binding: b, observed: observed, credential: credential}); e != nil {
			return organization.StoreResult{}, e
		}
		current, e := s.repository.ReadInvitation(bounded, organization.InvitationQuery{Operation: organization.InvitationReject, TenantID: b.TenantID, ActorID: actor.UserID, RecipientUserID: actor.UserID, OrganizationID: x.Organization.ID, InvitationID: x.Invitation.Record.ID})
		if e != nil {
			return organization.StoreResult{}, e
		}
		if current.Organization != rejection.Organization || current.RecipientUser != rejection.RecipientUser || current.RecipientIdentifier != rejection.RecipientIdentifier || current.Record.Invitation != rejection.Record.Invitation {
			return organization.StoreResult{}, organization.ErrForbidden
		}
	}
	if observed.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	if bounded.Err() != nil {
		return organization.StoreResult{}, bounded.Err()
	}
	if receipt.Outcome != identity.CommitOutcomeInvalid && receipt.Binding != b {
		return organization.StoreResult{}, organization.ErrUnavailable
	}
	return p.result(receipt), invitationPublicError(err)
}

// Only genuine current session custody is observed here. Reusing this native
// fence does not reconstruct the original private GetResult or renew execution.
func (s *InvitationService) observeInvitationRecovery(ctx context.Context, a organization.Authentication, actor identity.ActorID) (session.GetResult, session.Credential, error) {
	token, err := session.ParseToken(a.Bearer.Token())
	if err != nil {
		return session.GetResult{}, session.Credential{}, organization.ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return session.GetResult{}, session.Credential{}, organization.ErrForbidden
	}
	observed, err := s.config.Sessions.Get(ctx, session.GetRequest{TenantID: a.TenantID, Credential: credential})
	if err != nil {
		return session.GetResult{}, session.Credential{}, storageError(ctx, err)
	}
	if observed.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return session.GetResult{}, session.Credential{}, organization.ErrForbidden
	}
	b, err := observed.Session.Bindings()
	if err != nil || b.TenantID != a.TenantID || actor != "" && identity.ActorID(b.UserID) != actor {
		return session.GetResult{}, session.Credential{}, organization.ErrForbidden
	}
	actorBinding := identity.CommandBinding{TenantID: b.TenantID, UserID: b.UserID, ActorID: identity.ActorID(b.UserID), ActorKind: authorization.SubjectUser}
	if _, _, _, err := sessionpg.OriginalSessionAdmission(s.actor.config.Profile, observed.Session, actorBinding); err != nil {
		return session.GetResult{}, session.Credential{}, organization.ErrForbidden
	}
	return observed, credential, nil
}

func (s *InvitationService) invitationSendRecoveryMember(ctx context.Context, a organization.Authentication, b identity.CommandBinding, org organization.ID, observed session.GetResult, credential session.Credential) (*recoveryInput, error) {
	v, err := s.core.Get(ctx, organization.ReadRequest{Authentication: a, OrganizationID: org, CorrelationID: b.CorrelationID})
	if err != nil {
		return nil, err
	}
	if v.Actor.Role != organization.RoleOwner {
		return nil, organization.ErrForbidden
	}
	b.RecordID = string(v.Organization.ID)
	return &recoveryInput{binding: b, observed: observed, credential: credential, organization: v.Organization, member: v.Actor}, nil
}

// Exact mapped-origin custody is independent of the public generic Recover's
// journal declaration. Only the authenticated mapping decoder can select this
// path; mapping itself remains correlation, never outcome/execution authority.
func (s *InvitationService) recoverMappedInvitationSend(ctx context.Context, a organization.Authentication, owner *invitationOperationInvocation, original invitationOperationInput) (organization.StoreResult, error) {
	b := original.Spec.Binding
	if a.TenantID != b.TenantID {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	observed, credential, err := s.observeInvitationRecovery(ctx, a, b.ActorID)
	if err != nil {
		return organization.StoreResult{}, err
	}
	current, err := s.invitationSendRecoveryMember(ctx, a, b, original.OrganizationID, observed, credential)
	if err != nil {
		return organization.StoreResult{}, err
	}
	recipient, err := s.repository.resolveRecipient(ctx, b.TenantID, b.UserID, original.RecipientIdentifier.ID)
	if err != nil {
		return organization.StoreResult{}, err
	}
	if recipient.User != original.RecipientUser || recipient.Identifier != original.RecipientIdentifier {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Core.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(original.OrganizationID), Attributes: authorization.Attributes{"organization.policy-version": authorization.StringValue(strconv.FormatUint(current.organization.Version, 10))}}, Environment: authorization.Environment{Time: s.config.Core.Clock.Now()}}}
	decision, err := s.config.Authorization.Decide(ctx, caller)
	if err != nil {
		return organization.StoreResult{}, organization.ErrUnavailable
	}
	if decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
	query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	owner.recoveryOrganization = original.OrganizationID
	receipt, recoverErr := owner.coordinator.ExpirePreparedFeatureCommand(ctx, query, caller, owner.registration(), owner)
	// Current disclosure callbacks are not leases. Reuse the actual membership
	// and session owner's final fences, then re-read the exact verified recipient.
	native := Service{participant: s.actor, config: ServiceConfig{Core: s.config.Core, Sessions: s.config.Sessions}}
	if err := native.revalidateRecovery(ctx, current); err != nil {
		return organization.StoreResult{}, err
	}
	final, err := s.repository.resolveRecipient(ctx, b.TenantID, b.UserID, original.RecipientIdentifier.ID)
	if err != nil {
		return organization.StoreResult{}, err
	}
	if final.User != recipient.User || final.Identifier != recipient.Identifier || final.Verification != recipient.Verification || final.UserAuthorityVersion != recipient.UserAuthorityVersion || final.IdentifierAuthorityVersion != recipient.IdentifierAuthorityVersion || final.CredentialAuthorityVersion != recipient.CredentialAuthorityVersion || observed.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	if ctx.Err() != nil {
		return organization.StoreResult{}, ctx.Err()
	}
	if receipt.Binding != b {
		if recoverErr != nil && receipt.Binding == (identity.CommandBinding{}) {
			return organization.StoreResult{}, invitationPublicError(recoverErr)
		}
		return organization.StoreResult{}, organization.ErrUnavailable
	}
	out := invitationOperationCorrelation(original)
	out.Receipt = receipt
	return out, invitationPublicError(recoverErr)
}

func (s *InvitationService) recoverPrepared(ctx context.Context, p *invitationPhase) (organization.StoreResult, error) {
	if p.input.Session.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	result, err := s.Recover(ctx, organization.Authentication{TenantID: p.input.Binding.TenantID, Bearer: p.input.Bearer}, InvitationRecovery{Binding: p.input.Binding, OrganizationID: p.input.Organization.ID})
	if (p.input.Operation == organization.InvitationCancel || p.input.Operation == organization.InvitationReject || p.input.Operation == organization.InvitationExpire || p.input.Operation == organization.InvitationResend) && p.input.Session.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	return result, err
}
func invitationPublicError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{organization.ErrInvalidInput, organization.ErrForbidden, organization.ErrConflict, organization.ErrLimit, organization.ErrLastOwner, organization.ErrUnavailable} {
		if errors.Is(err, known) {
			return known
		}
	}
	var forbidden identity.ForbiddenError
	var conflict identity.ConflictError
	var unknown identity.UnknownCommitError
	var invalid identity.InvalidInputError
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.As(err, &forbidden):
		return organization.ErrForbidden
	case errors.As(err, &conflict):
		return organization.ErrConflict
	case errors.As(err, &invalid):
		return organization.ErrInvalidInput
	case errors.As(err, &unknown):
		return err
	default:
		return organization.ErrUnavailable
	}
}
