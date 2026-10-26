package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

type invitationPhase struct {
	service       *InvitationService
	root          organization.Command
	input         organization.CommandInput
	command       identity.Command
	counters      kernel.CommandCounterPlan
	occurred      time.Time
	recipient     kernel.RecipientRecord
	capability    kernel.CapabilityPlan
	envelope      [32]byte
	replayVersion uint32
	registry      *kernel.ContributorRegistry
	coordinator   *kernel.Coordinator
	execution     *invitationExecution
	applied       bool
	naturalCancel bool
	naturalReject bool
	naturalExpire bool
}

var _ kernel.OrganizationInvitationIssuanceContributor = (*invitationPhase)(nil)
var _ kernel.OrganizationInvitationConsumptionContributor = (*invitationPhase)(nil)
var _ organization.UnitOfWork = (*invitationPhase)(nil)

func (*invitationPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.invitation", Version: 1}
}
func (*invitationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{organization.InvitationSend.Descriptor(), organization.InvitationAccept.Descriptor(), organization.InvitationCancel.Descriptor(), organization.InvitationReject.Descriptor(), organization.InvitationExpire.Descriptor(), organization.InvitationResend.Descriptor()}
}

func (p *invitationPhase) mapCommand() error {
	x := p.input
	f, err := sessionpg.OriginalSessionFields(x.Session.Session)
	if err != nil {
		return identity.ForbiddenError{}
	}
	i := x.Invitation.Record
	f = append(f, text("id", string(x.Organization.ID)), number("version", x.Organization.Version), number("actor-version", x.Actor.Version), text("actor-role", string(x.Actor.Role)), number("actor-authorization", x.Actor.AuthorizationVersion), number("member-version", x.Target.Version), text("member-role", string(x.Target.Role)), number("member-authorization", x.Target.AuthorizationVersion), number("target-version", x.TargetUser.Version), text("target-status", string(x.TargetUser.Status)), text("role", string(i.Role)), number("maximum-members", x.MaximumMembers), number("maximum-per-user", x.MaximumPerUser), number("maximum-per-tenant", x.MaximumPerTenant), number("maximum-pending", x.Invitation.MaximumPending), number("invitation-version", i.Version), text("recipient-identifier", string(i.RecipientIdentifierID)), number("recipient-identifier-version", i.RecipientIdentifierVersion), identity.FeatureField{Name: "organization.invitation-expires-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: i.ExpiresAt}}, text("session-until", x.Session.ValidUntil().UTC().Format(time.RFC3339Nano)))
	if x.Operation == organization.InvitationCancel || x.Operation == organization.InvitationReject || x.Operation == organization.InvitationExpire || x.Operation == organization.InvitationResend {
		// Terminal withdrawals retain the invitation's historical recipient and
		// creator in keyed identity without changing legacy send/accept bytes.
		f = append(f, text("invitation-recipient", string(i.RecipientUserID)), text("invitation-created-by", string(i.CreatedBy)))
	}
	if x.Operation == organization.InvitationExpire {
		f = append(f, text("expiry-reason", string(x.Invitation.ExpirationReason)))
	}
	if x.Operation == organization.InvitationResend {
		f = append(f, number("invitation-issued-version", i.IssuedVersion))
	}
	p.command, err = identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: x.Binding, Operation: x.Operation.Descriptor(), Fields: f}, x.Bearer)
	return err
}

func (p *invitationPhase) loadCapability(ctx context.Context) error {
	x := p.input
	var envelope []byte
	var version *int64
	err := p.service.actor.repository.pool.Raw().QueryRow(ctx, `SELECT capability_envelope,capability_replay_key_version FROM organization.invitations WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3`, string(x.Binding.TenantID), string(x.Organization.ID), x.Binding.RecordID).Scan(&envelope, &version)
	defer clear(envelope)
	if err != nil {
		return storageError(ctx, err)
	}
	if len(envelope) != 32 || version == nil || *version < 1 || *version > 4294967295 {
		return organization.ErrForbidden
	}
	copy(p.envelope[:], envelope)
	p.replayVersion = uint32(*version)
	p.capability, err = p.verifyCapability(ctx)
	return err
}
func (p *invitationPhase) verifyCapability(ctx context.Context) (kernel.CapabilityPlan, error) {
	i := p.input.Invitation.Record
	return p.service.issuer.PrepareOrganizationInvitationConsumption(ctx, p.input.Binding, p.input.Invitation.Proof, p.envelope, p.replayVersion, issuerpg.OrganizationInvitationScope{OrganizationID: string(i.OrganizationID), InvitationVersion: i.Version, Role: string(i.Role), RecipientIdentifierID: i.RecipientIdentifierID, RecipientIdentifierVersion: i.RecipientIdentifierVersion})
}

func (p *invitationPhase) compose() error {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return err
	}
	contributors := []kernel.Contributor{p.service.actor.repository.directory, a, l, p.service.config.Risk, p}
	if invitationIssuance(p.input.Operation) {
		contributors = append(contributors, p.service.issuer, p.service.config.Delivery.Owner)
	} else if p.input.Operation == organization.InvitationAccept {
		contributors = append(contributors, issuerpg.NewParticipant())
	}
	p.registry, err = kernel.NewContributorRegistry(contributors)
	if err != nil {
		return err
	}
	p.coordinator, err = kernel.NewCoordinator(p.service.actor.repository.pool, p.registry, p.service.config.Coordinator)
	return err
}
func (p *invitationPhase) lifecycle() (string, string) {
	if p.input.Operation == organization.InvitationResend {
		return "invitation.resent.v1", "identity.organization.resend_invitation"
	}
	if p.input.Operation == organization.InvitationExpire {
		return "invitation.expired.v1", "identity.organization.expire_invitation"
	}
	if p.input.Operation == organization.InvitationReject {
		return "invitation.rejected.v1", "identity.organization.reject_invitation"
	}
	if p.input.Operation == organization.InvitationCancel {
		return "invitation.cancelled.v1", "identity.organization.cancel_invitation"
	}
	if p.input.Operation == organization.InvitationSend {
		return "invitation.created.v1", "identity.organization.create_invitation"
	}
	return "invitation.accepted.v1", "identity.organization.accept_invitation"
}
func (p *invitationPhase) retention() string {
	// SECURITY_EVENTS selects standard retention for withdrawals; historical
	// send/accept profiles retain their installed protected classification.
	if p.input.Operation == organization.InvitationCancel || p.input.Operation == organization.InvitationReject || p.input.Operation == organization.InvitationExpire || p.input.Operation == organization.InvitationResend {
		return "standard"
	}
	return "protected"
}
func (p *invitationPhase) plan(final bool) (kernel.CommandPlan, error) {
	spec, ok := p.command.Feature()
	if !ok {
		return kernel.CommandPlan{}, identity.InvalidInputError{Field: "invitation"}
	}
	event, action := p.lifecycle()
	b := p.input.Binding
	v := p.input.Invitation.Record.Version
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.occurred, Action: action, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "invitation", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "invitation", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(v, 10), "aggregate.after_version": strconv.FormatUint(v+1, 10), "retention.class": p.retention()}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, spec.Operation, "invitation", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	contributors := []kernel.ContributorDescriptor{}
	for _, d := range p.registry.Descriptors() {
		if d.ContractID != "capability.issuance" && d.ContractID != "identity.delivery.effects" {
			contributors = append(contributors, d)
		}
	}
	plan := kernel.CommandPlan{Contributors: contributors, Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: spec.Operation}, SubjectType: "invitation", Lifecycle: &kernel.LifecyclePlan{EventType: event, BeforeVersion: v, AfterVersion: v + 1}, CommandCounters: &p.counters, Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: p.retention(), BindingDigest: digest}}}
	if p.input.Operation == organization.InvitationCancel || p.input.Operation == organization.InvitationReject || p.input.Operation == organization.InvitationExpire {
		return p.coordinator.PrepareCommandPlan(b, p.command, plan)
	}
	if p.input.Operation == organization.InvitationAccept {
		plan.Capability = &p.capability
		return p.coordinator.PrepareCommandPlan(b, p.command, plan)
	}
	if p.input.Operation == organization.InvitationSend {
		plan.OrganizationInvitationOrigin = &kernel.OrganizationInvitationOriginPlan{OrganizationID: string(p.input.Organization.ID), OrganizationVersion: p.input.Organization.Version}
	}
	if !final {
		return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
	}
	if p.execution == nil {
		return kernel.CommandPlan{}, identity.InvalidInputError{Field: "invitation"}
	}
	issue, err := p.execution.issuance.Plan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	delivery, err := p.execution.delivery.Plan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.CapabilityIssuance = &issue
	plan.Delivery = &delivery
	plan.Contributors = append(plan.Contributors, issue.Contributor, delivery.Contributor)
	return p.coordinator.PrepareCommandPlan(b, p.command, plan)
}
func (p *invitationPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c != p.command {
		return identity.InvalidInputError{Field: "invitation"}
	}
	spec, ok := c.Feature()
	event, action := p.lifecycle()
	v := p.input.Invitation.Record.Version
	if !ok || spec.Operation != p.input.Operation.Descriptor() || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != spec.Operation || plan.SubjectType != "invitation" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: event, BeforeVersion: v, AfterVersion: v + 1}) || plan.CommandCounters == nil || *plan.CommandCounters != p.counters || len(plan.Audits) != 1 || plan.Audits[0].EventType != action || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != p.retention() || plan.OTP != nil {
		return identity.InvalidInputError{Field: "invitation"}
	}
	if p.input.Operation == organization.InvitationSend {
		origin := kernel.OrganizationInvitationOriginPlan{OrganizationID: string(p.input.Organization.ID), OrganizationVersion: p.input.Organization.Version}
		if plan.Capability != nil || plan.OrganizationInvitationOrigin == nil || *plan.OrganizationInvitationOrigin != origin {
			return identity.InvalidInputError{Field: "invitation"}
		}
	} else if p.input.Operation == organization.InvitationResend {
		if plan.Capability != nil || plan.OrganizationInvitationOrigin != nil {
			return identity.InvalidInputError{Field: "invitation"}
		}
	} else if p.input.Operation == organization.InvitationCancel || p.input.Operation == organization.InvitationReject || p.input.Operation == organization.InvitationExpire {
		if plan.Capability != nil || plan.CapabilityIssuance != nil || plan.Delivery != nil || plan.OrganizationInvitationOrigin != nil {
			return identity.InvalidInputError{Field: "invitation"}
		}
	} else if plan.Capability == nil || *plan.Capability != p.capability || plan.CapabilityIssuance != nil || plan.Delivery != nil || plan.OrganizationInvitationOrigin != nil {
		return identity.InvalidInputError{Field: "invitation"}
	}
	return nil
}
func (p *invitationPhase) ValidateOrganizationInvitationIssuance(c identity.Command, plan kernel.CommandPlan) error {
	if err := p.ValidateFeatureCommand(c, plan); err != nil {
		return err
	}
	if !invitationIssuance(p.input.Operation) || plan.CapabilityIssuance == nil || plan.Delivery == nil || len(plan.CapabilityIssuance.Grants) != 1 || len(plan.Delivery.Intents) != 1 {
		return identity.InvalidInputError{Field: "invitation"}
	}
	g, d := plan.CapabilityIssuance.Grants[0], plan.Delivery.Intents[0]
	if string(g.Purpose) != organization.InvitationAccept.Descriptor().OperationID || g.MaxUses != 1 || !g.ExpiresAt.Equal(p.input.Invitation.Record.ExpiresAt) || d.SubjectID != string(p.input.Binding.UserID) || d.Purpose != string(g.Purpose) || !d.ExpiresAt.Equal(g.ExpiresAt) {
		return identity.InvalidInputError{Field: "invitation"}
	}
	return nil
}
func (p *invitationPhase) ValidateOrganizationInvitationConsumption(c identity.Command, plan kernel.CapabilityPlan) error {
	if p == nil || c != p.command || p.input.Operation != organization.InvitationAccept || plan != p.capability {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.service.config.Issuer.PreparationTimeout)
	defer cancel()
	verified, err := p.verifyCapability(ctx)
	if err != nil {
		return err
	}
	if verified != plan {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *invitationPhase) admit(ctx context.Context, w kernel.Work, final bool) error {
	if ctx == nil {
		return identity.InvalidInputError{Field: "invitation"}
	}
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	x := p.input
	s, err := x.Session.Session.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	bearer, ok := p.command.SessionToken()
	if !ok {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	key, ok := p.service.actor.config.LookupKeys[s.Lookup.KeyVersion]
	if !ok {
		return identity.ForbiddenError{}
	}
	digest, err := token.Digest(key, string(s.TenantID))
	if err != nil || digest.KeyVersion != s.Lookup.KeyVersion || subtle.ConstantTimeCompare(digest.Sum[:], s.Lookup.Sum[:]) != 1 {
		return identity.ForbiddenError{}
	}
	b := x.Binding
	b.UserID = identity.UserID(b.ActorID)
	d, credential, policy, err := sessionpg.OriginalSessionAdmission(p.service.actor.config.Profile, x.Session.Session, b)
	if err != nil {
		return identity.ForbiddenError{}
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, d); err != nil {
		return err
	}
	if _, err = w.RequireActiveActorCredential(ctx, p, credential); err != nil {
		return err
	}
	if err = w.RequireActiveActorAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err = sessionpg.RequireSession(ctx, w, p.service.actor.config.Session, x.Session.Session); err != nil {
		return err
	}
	if x.Operation == organization.InvitationCancel || x.Operation == organization.InvitationExpire {
		// Withdrawing an invitation must remain possible after recipient email
		// removal/suspension; only the authenticated administrator is admitted.
	} else if !final && invitationIssuance(x.Operation) {
		err = w.RequireOrganizationInvitationRecipient(ctx, p, p.recipient)
	} else {
		err = w.RequireRecipient(ctx, p, p.recipient)
	}
	if err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	// API_OPERATIONS' explicit expiry closes pending rows before or after the
	// natural deadline; that does not renew the actor's original session lease.
	if !now.Before(x.Session.ValidUntil()) || x.Session.ValidUntil().After(now.Add(20*time.Second)) || x.Operation != organization.InvitationExpire && !now.Before(x.Invitation.Record.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *invitationPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return p.admit(ctx, w, true)
}

func (p *invitationPhase) Execute(ctx context.Context, c organization.Command) (organization.StoreResult, error) {
	if ctx == nil || p == nil || c != p.root {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	plan, err := p.plan(false)
	if err != nil {
		return organization.StoreResult{}, err
	}
	if invitationIssuance(p.input.Operation) {
		p.applied = false
		receipt, err := p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
		if p.input.Operation == organization.InvitationResend && !p.applied && err == nil && receipt.Outcome != identity.CommitOutcomeUnknown && receipt.Outcome != identity.CommitOutcomeInvalid {
			// Only retained history skips Apply's current protected fences. A
			// fresh known commit must survive a later metadata failure unchanged.
			return p.service.recoverPrepared(ctx, p)
		}
		return p.result(receipt), err
	}
	reservation, receipt, err := p.coordinator.ReserveCommand(ctx, p.input.Binding, p.command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		if (p.input.Operation == organization.InvitationCancel || p.input.Operation == organization.InvitationReject || p.input.Operation == organization.InvitationExpire) && err == nil && receipt.Outcome != identity.CommitOutcomeInvalid {
			// Retained receipts bypass Apply's protected admission. They are
			// historical disclosure, not permission supplied by the old bearer
			// or membership snapshot; use the same current recovery authority.
			return p.service.recoverPrepared(ctx, p)
		}
		return p.result(receipt), err
	}
	w, err := p.coordinator.Begin(ctx, reservation)
	if err != nil {
		return p.result(identity.CommandResult{Binding: p.input.Binding, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: p.input.Operation.Descriptor()}}), err
	}
	defer p.coordinator.Abort(w, identity.UnavailableError{})
	receipt, err = p.coordinator.ApplyFeature(ctx, w, p.command)
	if err != nil {
		receipt, err = p.coordinator.Abort(w, err)
		return p.result(receipt), err
	}
	receipt, err = p.coordinator.Commit(w, receipt)
	return p.result(receipt), err
}
func (p *invitationPhase) result(r identity.CommandResult) organization.StoreResult {
	return organization.StoreResult{Receipt: r, OrganizationID: p.input.Organization.ID, MemberID: p.input.Binding.UserID, InvitationID: p.input.Invitation.Record.ID}
}
func (p *invitationPhase) Recover(ctx context.Context, id identity.CommandID) (organization.StoreResult, error) {
	// Execute is scoped to this exact original invocation. Metadata-only public
	// recovery authenticates afresh; neither this ID nor a historical receipt
	// can substitute for current actor/organization policy.
	if p == nil || ctx == nil || id != p.input.Binding.CommandID {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	return p.service.recoverPrepared(ctx, p)
}

func (p *invitationPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return recoverInvitationParticipant(ctx, w, p, p.input.Organization.ID)
}

// Recovery's instance guard belongs to the registered participant, including a
// request-custody facade. The negative evidence still has this one native owner.
func recoverInvitationParticipant(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor, organizationID organization.ID) (kernel.RecoveryStatus, error) {
	b, f, l, err := w.FeatureScope(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if f.Contributor != owner.Descriptor() {
		return kernel.RecoveryUnknown, identity.InvalidInputError{Field: "invitation"}
	}
	rows, err := w.Query(ctx, `SELECT tenant_id,organization_id,invitation_id,user_id,actor_id,operation,before_version::text,after_version::text FROM organization.command_effects WHERE command_id=$1`, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var tenant, org, invite, user, actor, op, before, after string
	if err = rows.Scan(&tenant, &org, &invite, &user, &actor, &op, &before, &after); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if err = rows.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if tenant != string(b.TenantID) || org != string(organizationID) || invite != b.RecordID || user != string(b.UserID) || actor != string(b.ActorID) || op != b.OperationID || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}

func invitationDigest(wire []byte) [32]byte { return sha256.Sum256(wire) }

func invitationIssuance(op organization.Operation) bool {
	return op == organization.InvitationSend || op == organization.InvitationResend
}
