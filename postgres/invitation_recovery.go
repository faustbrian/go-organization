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
	if (op != organization.InvitationSend && op != organization.InvitationAccept && op != organization.InvitationCancel && op != organization.InvitationReject) || b.ValidateFor(op.Descriptor()) != nil || b.PolicyID != s.config.Core.PolicyID || b.PolicyVersion != s.config.Core.PolicyVersion || b.ActorKind != authorization.SubjectUser || !scope(string(recovery.OrganizationID)) {
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
	token, err := session.ParseToken(a.Bearer.Token())
	if err != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	observed, err := s.config.Sessions.Get(bounded, session.GetRequest{TenantID: a.TenantID, Credential: credential})
	if err != nil {
		return organization.StoreResult{}, storageError(bounded, err)
	}
	if observed.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	actor, err := observed.Session.Bindings()
	if err != nil || actor.UserID != identity.UserID(b.ActorID) || actor.TenantID != b.TenantID {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	actorBinding := b
	actorBinding.UserID = actor.UserID
	if _, _, _, err = sessionpg.OriginalSessionAdmission(s.actor.config.Profile, observed.Session, actorBinding); err != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	var version uint64
	var cancellation *recoveryInput
	var rejection *organization.InvitationSnapshot
	query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	if x.Operation == organization.InvitationCancel {
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
		v, err := s.core.Get(bounded, organization.ReadRequest{Authentication: a, OrganizationID: x.Organization.ID, CorrelationID: b.CorrelationID})
		if err != nil {
			return organization.StoreResult{}, err
		}
		if v.Actor.Role != organization.RoleOwner {
			return organization.StoreResult{}, organization.ErrForbidden
		}
		version = v.Organization.Version
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
func (s *InvitationService) recoverPrepared(ctx context.Context, p *invitationPhase) (organization.StoreResult, error) {
	if p.input.Session.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	result, err := s.Recover(ctx, organization.Authentication{TenantID: p.input.Binding.TenantID, Bearer: p.input.Bearer}, InvitationRecovery{Binding: p.input.Binding, OrganizationID: p.input.Organization.ID})
	if (p.input.Operation == organization.InvitationCancel || p.input.Operation == organization.InvitationReject) && p.input.Session.ValidateAt(s.config.Core.Clock.Now()) != nil {
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
