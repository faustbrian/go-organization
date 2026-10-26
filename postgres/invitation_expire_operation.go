package postgres

import (
	"context"
	"errors"
	"slices"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// Expire initiates a naturally repeatable exact-version invitation expiration.
// It allocates the command internally, uses the existing native preparation and
// execution once, and needs no recipient credential, current email or proof.
// Install InvitationExpireOperationMigrationSource before selecting this API.
// Network is the transport's trusted canonical full client address.
//
// Reconstructed matching committed requests return the actual original receipt
// under the original actor's current manager/session authority. CorrelationID is
// diagnostic only. A terminal/absent row is never success; legacy effects without
// original organization-version correlation fail closed. Unknown execution is
// returned immediately without another attempt. Retain its original receipt
// binding for the existing Recover API; an effect lookup cannot identify an
// unattached or uncommitted original command from natural request syntax alone.
func (s *InvitationService) Expire(ctx context.Context, r organization.InvitationExpireOperationRequest, network string) (out organization.StoreResult, err error) {
	if s == nil || s.root == nil || ctx == nil || r.Validate() != nil || !slices.Contains(s.config.Invitation.ExpirationReasons, r.Reason) || !operationNetwork(network) {
		return out, organization.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = organization.ErrUnavailable
		}
	}()
	observed, _, err := s.observeInvitationRecovery(ctx, r.Authentication, "")
	if err != nil {
		return out, err
	}
	actor, err := observed.Session.Bindings()
	if err != nil {
		return out, organization.ErrForbidden
	}
	if previous, found, err := s.expirationOutcome(ctx, r, actor.UserID); err != nil || found {
		return previous, err
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return out, organization.ErrUnavailable
	}
	prepared, err := s.PrepareExpire(ctx, organization.InvitationExpireRequest{Authentication: r.Authentication, CommandID: id, ID: r.InvitationID, OrganizationID: r.OrganizationID, OrganizationVersion: r.OrganizationVersion, InvitationVersion: r.InvitationVersion, Reason: r.Reason, CorrelationID: r.CorrelationID}, network)
	if err != nil {
		if errors.Is(err, organization.ErrConflict) || errors.Is(err, organization.ErrForbidden) {
			if previous, found, lookupErr := s.expirationOutcome(ctx, r, actor.UserID); lookupErr != nil || found {
				return previous, lookupErr
			}
		}
		return out, err
	}
	// This opt-in marker adds correlation to the existing atomic effect only.
	// Raw PrepareExpire/Execute remains independent of the optional migration.
	prepared.state.naturalExpire = true
	out, err = s.Execute(ctx, prepared)
	if errors.Is(err, organization.ErrConflict) {
		// The same pending/version fence can have committed a competing natural
		// request. Reconcile its real effect, never infer a receipt from the row.
		if previous, found, lookupErr := s.expirationOutcome(ctx, r, actor.UserID); lookupErr != nil || found {
			return previous, lookupErr
		}
	}
	return out, err
}

// The partial unique index bounds this probe to one committed expiration for
// the exact invitation epoch. Actor filters retain original initiator scope;
// nullable correlation cannot be backfilled from today's organization version.
const expirationOperationLookupSQL = `SELECT command_id,expire_organization_version::text,expire_reason
FROM organization.command_effects
WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3
AND before_version=$4::numeric AND operation='identity.organization.invitation.expire'
AND actor_id=$5 AND user_id=$5 LIMIT 2`

func (s *InvitationService) expirationOutcome(ctx context.Context, r organization.InvitationExpireOperationRequest, actor identity.UserID) (organization.StoreResult, bool, error) {
	// API_OPERATIONS assigns expiration org:invite, independently of Get's
	// org:read. Keep the repository's current manager fence here; PrepareExpire
	// and Recover own the expiration action and final session checks.
	view, err := s.repository.ReadInvitation(ctx, organization.InvitationQuery{Operation: organization.InvitationExpire, TenantID: r.Authentication.TenantID, OrganizationID: r.OrganizationID, InvitationID: r.InvitationID, ActorID: actor})
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	rows, err := s.actor.repository.pool.Raw().Query(ctx, expirationOperationLookupSQL, string(r.Authentication.TenantID), string(r.OrganizationID), string(r.InvitationID), strconv.FormatUint(r.InvitationVersion, 10), string(actor))
	if err != nil {
		return organization.StoreResult{}, false, storageError(ctx, err)
	}
	var id identity.CommandID
	var version, reason *string
	count := 0
	for rows.Next() {
		count++
		if rows.Scan(&id, &version, &reason) != nil || count > 1 {
			rows.Close()
			return organization.StoreResult{}, false, organization.ErrUnavailable
		}
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return organization.StoreResult{}, false, storageError(ctx, readErr)
	}
	if count == 0 {
		return organization.StoreResult{}, false, nil
	}
	if _, err := identity.ParseCommandID(string(id)); err != nil || version == nil || reason == nil {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	// The native scanner derives a positive issued epoch from pending/terminal
	// versions even on pre-resend schemas; zero is never a legacy-row match.
	if *version != strconv.FormatUint(r.OrganizationVersion, 10) || *reason != string(r.Reason) || view.Record.Invitation.Status != organization.InvitationExpired || view.Record.Invitation.Version != r.InvitationVersion+1 || view.Record.Invitation.IssuedVersion != r.InvitationVersion {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	p := &invitationPhase{service: s, input: organization.CommandInput{Operation: organization.InvitationExpire}}
	if err := p.compose(); err != nil {
		return organization.StoreResult{}, false, invitationPublicError(err)
	}
	query := identity.RecoveryQuery{CommandID: id, TenantID: r.Authentication.TenantID, UserID: actor, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, OperationID: string(organization.InvitationExpire), RecordID: string(r.InvitationID)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Coordinator.QueryPolicy.PolicyVersion), CorrelationID: r.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(query.TenantID), Subject: authorization.Subject{Kind: query.ActorKind, ID: authorization.SubjectID(actor)}, Action: authorization.Action(query.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(actor)}}}
	original, err := p.coordinator.QueryCommand(ctx, query, caller)
	if err != nil {
		return organization.StoreResult{}, false, invitationPublicError(err)
	}
	if original.Validate() != nil || original.Binding.ValidateFor(organization.InvitationExpire.Descriptor()) != nil || original.Feature == nil || *original.Feature != organization.InvitationExpire.Descriptor() {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	out, err := s.Recover(ctx, r.Authentication, InvitationRecovery{Binding: original.Binding, OrganizationID: r.OrganizationID})
	if err == nil && (out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature == nil || out.Receipt.Feature.BeforeVersion != r.InvitationVersion || out.Receipt.Feature.AfterVersion != r.InvitationVersion+1) {
		err = organization.ErrUnavailable
	}
	return out, true, invitationPublicError(err)
}
