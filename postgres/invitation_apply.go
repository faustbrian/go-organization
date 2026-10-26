package postgres

import (
	"context"
	"crypto/subtle"
	"strconv"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

// currentDomain runs solely in existing coordinator Work. Its tenant advisory
// serialization precedes primary authority and these domain locks. The selected
// membership profile's tenant row also bounds cross-organization cardinality.
// No callbacks or network operations occur under these locks.
func (p *invitationPhase) currentDomain(ctx context.Context, w kernel.Work) (int64, error) {
	x := p.input
	b := x.Binding
	var version, state string
	var members, owners int64
	rows, err := w.Query(ctx, `SELECT version::text,state,member_count,owner_count FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 FOR UPDATE`, string(b.TenantID), string(x.Organization.ID))
	if err = one(rows, err, &version, &state, &members, &owners); err != nil {
		return 0, err
	}
	if state != "active" {
		return 0, identity.ForbiddenError{}
	}
	// Resend advances only the invitation's issued version; its organization
	// epoch is read-only. Preserve the existing overflow guard for other paths,
	// including acceptance, which advances organization authority.
	if version != strconv.FormatUint(x.Organization.Version, 10) || x.Organization.Version == ^uint64(0) && x.Operation != organization.InvitationResend {
		return 0, identity.ConflictError{}
	}
	if members < 1 || owners < 1 || owners > members {
		return 0, identity.UnavailableError{}
	}
	if invitationIssuance(x.Operation) || x.Operation == organization.InvitationCancel || x.Operation == organization.InvitationExpire {
		actor, err := readMember(ctx, w, b.TenantID, x.Organization.ID, identity.UserID(b.ActorID))
		if err != nil {
			return 0, err
		}
		if !actor.Active || actor.Role != x.Actor.Role || actor.Role != organization.RoleOwner && ((x.Operation != organization.InvitationCancel && x.Operation != organization.InvitationExpire && x.Operation != organization.InvitationResend) || actor.Role != organization.RoleAdministrator) || actor.Version != x.Actor.Version || actor.AuthorizationVersion != x.Actor.AuthorizationVersion {
			return 0, identity.ForbiddenError{}
		}
		scope, err := OrganizationAuthorityScope(b.TenantID, x.Organization.ID, actor.UserID)
		if err != nil {
			return 0, err
		}
		if err = authority.RequireAuthority(ctx, w, scope, actor.AuthorizationVersion, p.service.actor.config.Session.MaximumDuration); err != nil {
			return 0, authorityError(err)
		}
		if x.Operation == organization.InvitationCancel || x.Operation == organization.InvitationExpire {
			return members, nil
		}
	}
	if x.Operation == organization.InvitationReject {
		// Rejecting grants no membership or organization authority. Only the
		// recipient/session fence and the invitation's own pending version matter.
		return members, nil
	}
	target, err := readMember(ctx, w, b.TenantID, x.Organization.ID, b.UserID)
	if err != nil {
		return 0, err
	}
	if target.Active || target.Version != x.Target.Version || target.AuthorizationVersion != x.Target.AuthorizationVersion || target.Role != x.Target.Role || target.Version == ^uint64(0) {
		return 0, identity.ConflictError{}
	}
	if x.Operation == organization.InvitationSend {
		var pending int64
		var duplicate bool
		rows, err = w.Query(ctx, `SELECT (SELECT count(*) FROM organization.invitations WHERE tenant_id=$1 AND organization_id=$2 AND state='pending' AND expires_at>clock_timestamp()),EXISTS(SELECT 1 FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$3)`, string(b.TenantID), string(x.Organization.ID), b.RecordID)
		if err = one(rows, err, &pending, &duplicate); err != nil {
			return 0, err
		}
		if duplicate {
			return 0, identity.ConflictError{}
		}
		if pending < 0 {
			return 0, identity.UnavailableError{}
		}
		if uint64(pending) >= x.Invitation.MaximumPending {
			return 0, identity.ForbiddenError{}
		}
	}
	if x.Operation == organization.InvitationResend {
		if err := p.currentResend(ctx, w); err != nil {
			return 0, err
		}
	}
	return members, nil
}

func (p *invitationPhase) currentResend(ctx context.Context, w kernel.Work) error {
	i := p.input.Invitation.Record
	if i.Version == 0 || i.Version >= ^uint64(0)-1 || i.IssuedVersion != i.Version {
		return identity.ForbiddenError{}
	}
	var matches bool
	rows, err := w.Query(ctx, `SELECT state='pending' AND version=$4::numeric AND issued_version=version AND expires_at=$5 AND expires_at>clock_timestamp() AND recipient_user_id=$6 AND recipient_identifier_id=$7 AND recipient_identifier_version=$8::numeric AND created_by=$9 AND role='member' FROM organization.invitations WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3 FOR UPDATE`, string(i.TenantID), string(i.OrganizationID), string(i.ID), strconv.FormatUint(i.Version, 10), i.ExpiresAt, string(i.RecipientUserID), string(i.RecipientIdentifierID), strconv.FormatUint(i.RecipientIdentifierVersion, 10), string(i.CreatedBy))
	if err = one(rows, err, &matches); err != nil {
		return err
	}
	if !matches {
		return identity.ConflictError{}
	}
	return nil
}

func (p *invitationPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command || !invitationIssuance(p.input.Operation) {
		return identity.InvalidInputError{Field: "invitation"}
	}
	if err := p.admit(ctx, w, false); err != nil {
		return err
	}
	_, err := p.currentDomain(ctx, w)
	return err
}
func (p *invitationPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command {
		return identity.FeatureReceipt{}, identity.InvalidInputError{Field: "invitation"}
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	if err := p.admit(ctx, w, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	x := p.input
	b := x.Binding
	if _, err := w.Exec(ctx, `INSERT INTO organization.tenant_locks(tenant_id) VALUES($1) ON CONFLICT DO NOTHING`, string(b.TenantID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	var tenant string
	rows, err := w.Query(ctx, `SELECT tenant_id FROM organization.tenant_locks WHERE tenant_id=$1 FOR UPDATE`, string(b.TenantID))
	if err = one(rows, err, &tenant); err != nil {
		return identity.FeatureReceipt{}, err
	}
	members, err := p.currentDomain(ctx, w)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if invitationIssuance(x.Operation) {
		err = p.send(ctx, w)
	} else if x.Operation == organization.InvitationCancel {
		err = p.cancel(ctx, w)
	} else if x.Operation == organization.InvitationReject {
		err = p.reject(ctx, w)
	} else if x.Operation == organization.InvitationExpire {
		err = p.expire(ctx, w)
	} else {
		err = p.accept(ctx, w, members)
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	_, fingerprint, _, err := w.FeatureCommandIdentity(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	i := x.Invitation.Record
	if x.Operation == organization.InvitationResend {
		delivery, err := p.execution.delivery.Plan()
		if err != nil || len(delivery.Intents) != 1 {
			return identity.FeatureReceipt{}, identity.InvalidInputError{Field: "invitation"}
		}
		_, err = w.Exec(ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,invitation_id,user_id,actor_id,operation,fingerprint,before_version,after_version,delivery_effect_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::numeric,$10::numeric,$11)`, string(b.CommandID), string(b.TenantID), string(x.Organization.ID), b.RecordID, string(b.UserID), string(b.ActorID), b.OperationID, fingerprint[:], strconv.FormatUint(i.Version, 10), strconv.FormatUint(i.Version+1, 10), delivery.Intents[0].EffectID)
		return identity.FeatureReceipt{Operation: x.Operation.Descriptor(), BeforeVersion: i.Version, AfterVersion: i.Version + 1}, err
	}
	if x.Operation == organization.InvitationCancel && p.naturalCancel {
		// Only the initiating natural-repeat profile requires its optional
		// migration. The original organization epoch is correlation, not new
		// authority; write it with the existing effect, never after COMMIT.
		_, err = w.Exec(ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,invitation_id,user_id,actor_id,operation,fingerprint,before_version,after_version,cancel_organization_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::numeric,$10::numeric,$11::numeric)`, string(b.CommandID), string(b.TenantID), string(x.Organization.ID), b.RecordID, string(b.UserID), string(b.ActorID), b.OperationID, fingerprint[:], strconv.FormatUint(i.Version, 10), strconv.FormatUint(i.Version+1, 10), strconv.FormatUint(x.Organization.Version, 10))
		return identity.FeatureReceipt{Operation: x.Operation.Descriptor(), BeforeVersion: i.Version, AfterVersion: i.Version + 1}, err
	}
	if x.Operation == organization.InvitationReject && p.naturalReject {
		// Preserve the exact original organization epoch with this existing
		// effect. Raw explicit rejection does not select the optional schema.
		_, err = w.Exec(ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,invitation_id,user_id,actor_id,operation,fingerprint,before_version,after_version,reject_organization_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::numeric,$10::numeric,$11::numeric)`, string(b.CommandID), string(b.TenantID), string(x.Organization.ID), b.RecordID, string(b.UserID), string(b.ActorID), b.OperationID, fingerprint[:], strconv.FormatUint(i.Version, 10), strconv.FormatUint(i.Version+1, 10), strconv.FormatUint(x.Organization.Version, 10))
		return identity.FeatureReceipt{Operation: x.Operation.Descriptor(), BeforeVersion: i.Version, AfterVersion: i.Version + 1}, err
	}
	if x.Operation == organization.InvitationExpire && p.naturalExpire {
		// Correlate the original epoch and registered reason with this atomic
		// effect; today's terminal row cannot reconstruct original admission.
		// Raw explicit expiry stays independent of the optional wrapper schema.
		_, err = w.Exec(ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,invitation_id,user_id,actor_id,operation,fingerprint,before_version,after_version,expire_organization_version,expire_reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::numeric,$10::numeric,$11::numeric,$12)`, string(b.CommandID), string(b.TenantID), string(x.Organization.ID), b.RecordID, string(b.UserID), string(b.ActorID), b.OperationID, fingerprint[:], strconv.FormatUint(i.Version, 10), strconv.FormatUint(i.Version+1, 10), strconv.FormatUint(x.Organization.Version, 10), string(x.Invitation.ExpirationReason))
		return identity.FeatureReceipt{Operation: x.Operation.Descriptor(), BeforeVersion: i.Version, AfterVersion: i.Version + 1}, err
	}
	if _, err = w.Exec(ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,invitation_id,user_id,actor_id,operation,fingerprint,before_version,after_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::numeric,$10::numeric)`, string(b.CommandID), string(b.TenantID), string(x.Organization.ID), b.RecordID, string(b.UserID), string(b.ActorID), b.OperationID, fingerprint[:], strconv.FormatUint(i.Version, 10), strconv.FormatUint(i.Version+1, 10)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: x.Operation.Descriptor(), BeforeVersion: i.Version, AfterVersion: i.Version + 1}, nil
}

func (p *invitationPhase) expire(ctx context.Context, w kernel.Work) error {
	i := p.input.Invitation.Record
	// API_OPERATIONS declares explicit expiry of a pending row, not merely an
	// elapsed-deadline projection. The shared pending/version fence revokes all
	// old grants and serializes acceptance without touching membership authority.
	n, err := w.Exec(ctx, `UPDATE organization.invitations SET state='expired',version=version+1,expired_at=clock_timestamp(),expiry_reason=$10 WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3 AND state='pending' AND version=$4::numeric AND expires_at=$5 AND recipient_user_id=$6 AND recipient_identifier_id=$7 AND recipient_identifier_version=$8::numeric AND created_by=$9 AND role='member'`, string(i.TenantID), string(i.OrganizationID), string(i.ID), strconv.FormatUint(i.Version, 10), i.ExpiresAt, string(i.RecipientUserID), string(i.RecipientIdentifierID), strconv.FormatUint(i.RecipientIdentifierVersion, 10), string(i.CreatedBy), string(p.input.Invitation.ExpirationReason))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *invitationPhase) reject(ctx context.Context, w kernel.Work) error {
	i := p.input.Invitation.Record
	// As with cancellation, the native terminal row is the revocation fence.
	// Acceptance locks this same row before membership and cannot consume the
	// original capability after rejection, even if its signature remains valid.
	n, err := w.Exec(ctx, `UPDATE organization.invitations SET state='rejected',version=version+1,rejected_at=clock_timestamp() WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3 AND state='pending' AND version=$4::numeric AND expires_at=$5 AND expires_at>clock_timestamp() AND recipient_user_id=$6 AND recipient_identifier_id=$7 AND recipient_identifier_version=$8::numeric AND created_by=$9 AND role='member'`, string(i.TenantID), string(i.OrganizationID), string(i.ID), strconv.FormatUint(i.Version, 10), i.ExpiresAt, string(i.RecipientUserID), string(i.RecipientIdentifierID), strconv.FormatUint(i.RecipientIdentifierVersion, 10), string(i.CreatedBy))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *invitationPhase) cancel(ctx context.Context, w kernel.Work) error {
	i := p.input.Invitation.Record
	// The pending/version fence is shared with acceptance. The original issued
	// capability may remain cryptographically valid, but cannot cross this
	// terminal transition; any concurrent capability consumption rolls back.
	n, err := w.Exec(ctx, `UPDATE organization.invitations SET state='cancelled',version=version+1,cancelled_at=clock_timestamp() WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3 AND state='pending' AND version=$4::numeric AND expires_at=$5 AND expires_at>clock_timestamp() AND recipient_user_id=$6 AND recipient_identifier_id=$7 AND recipient_identifier_version=$8::numeric AND created_by=$9 AND role='member'`, string(i.TenantID), string(i.OrganizationID), string(i.ID), strconv.FormatUint(i.Version, 10), i.ExpiresAt, string(i.RecipientUserID), string(i.RecipientIdentifierID), strconv.FormatUint(i.RecipientIdentifierVersion, 10), string(i.CreatedBy))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *invitationPhase) send(ctx context.Context, w kernel.Work) error {
	if p.execution == nil {
		return identity.InvalidInputError{Field: "invitation"}
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return err
	}
	digest := invitationDigest(wire)
	clear(wire)
	if generation != p.execution.generation || digest != p.execution.digest {
		return identity.InvalidInputError{Field: "invitation"}
	}
	issue, err := p.execution.issuance.Plan()
	if err != nil || len(issue.Grants) != 1 {
		return identity.InvalidInputError{Field: "invitation"}
	}
	delivery, err := p.execution.delivery.Plan()
	if err != nil || len(delivery.Intents) != 1 {
		return identity.InvalidInputError{Field: "invitation"}
	}
	if err = p.service.issuer.Stage(ctx, w, p.execution.issuance); err != nil {
		return err
	}
	if err = p.service.config.Delivery.Owner.Stage(ctx, w, p.execution.delivery); err != nil {
		return err
	}
	x := p.input
	b := x.Binding
	i := x.Invitation.Record
	g := issue.Grants[0]
	if x.Operation == organization.InvitationResend {
		n, err := w.Exec(ctx, `UPDATE organization.invitations SET version=version+1,issued_version=issued_version+1,delivery_effect_id=$10,capability_envelope=$11,capability_replay_key_version=$12 WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3 AND state='pending' AND version=$4::numeric AND issued_version=version AND version<18446744073709551614 AND expires_at=$5 AND expires_at>clock_timestamp() AND recipient_user_id=$6 AND recipient_identifier_id=$7 AND recipient_identifier_version=$8::numeric AND created_by=$9 AND role='member'`, string(i.TenantID), string(i.OrganizationID), string(i.ID), strconv.FormatUint(i.Version, 10), i.ExpiresAt, string(i.RecipientUserID), string(i.RecipientIdentifierID), strconv.FormatUint(i.RecipientIdentifierVersion, 10), string(i.CreatedBy), delivery.Intents[0].EffectID, g.ProofFingerprint[:], int64(g.ReplayKeyVersion))
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
		return nil
	}
	_, err = w.Exec(ctx, `INSERT INTO organization.invitations(tenant_id,organization_id,invitation_id,recipient_user_id,recipient_identifier_id,recipient_identifier_version,created_by,role,state,version,expires_at,delivery_effect_id,capability_envelope,capability_replay_key_version) VALUES($1,$2,$3,$4,$5,$6::numeric,$7,'member','pending',1,$8,$9,$10,$11)`, string(b.TenantID), string(i.OrganizationID), string(i.ID), string(i.RecipientUserID), string(i.RecipientIdentifierID), strconv.FormatUint(i.RecipientIdentifierVersion, 10), string(b.ActorID), i.ExpiresAt, delivery.Intents[0].EffectID, g.ProofFingerprint[:], int64(g.ReplayKeyVersion))
	return err
}
func (p *invitationPhase) accept(ctx context.Context, w kernel.Work, members int64) error {
	x := p.input
	b := x.Binding
	i := x.Invitation.Record
	reservation, err := w.OrganizationInvitationConsumption(p)
	if err != nil {
		return err
	}
	if reservation.Command != b || reservation.Plan != p.capability {
		return identity.ForbiddenError{}
	}
	var state, version, identifierVersion, user, identifier, role, creator string
	var expires time.Time
	var envelope []byte
	var replayVersion *int64
	rows, err := w.Query(ctx, `SELECT state,version::text,recipient_user_id,recipient_identifier_id,recipient_identifier_version::text,role,created_by,expires_at,capability_envelope,capability_replay_key_version FROM organization.invitations WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3 FOR UPDATE`, string(b.TenantID), string(i.OrganizationID), string(i.ID))
	err = one(rows, err, &state, &version, &user, &identifier, &identifierVersion, &role, &creator, &expires, &envelope, &replayVersion)
	defer clear(envelope)
	if err != nil {
		return err
	}
	if state != "pending" || version != strconv.FormatUint(i.Version, 10) {
		return identity.ConflictError{}
	}
	if user != string(b.UserID) || identifier != string(i.RecipientIdentifierID) || identifierVersion != strconv.FormatUint(i.RecipientIdentifierVersion, 10) || role != "member" || creator != string(i.CreatedBy) || !expires.Equal(i.ExpiresAt) || len(envelope) != 32 || subtle.ConstantTimeCompare(envelope, p.envelope[:]) != 1 || replayVersion == nil || *replayVersion != int64(p.replayVersion) {
		return identity.ForbiddenError{}
	}
	if uint64(members) >= x.MaximumMembers {
		return identity.ForbiddenError{}
	}
	var memberOf int64
	rows, err = w.Query(ctx, `SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, string(b.TenantID), string(b.UserID))
	if err = one(rows, err, &memberOf); err != nil {
		return err
	}
	if memberOf < 0 {
		return identity.UnavailableError{}
	}
	if uint64(memberOf) >= x.MaximumPerUser {
		return identity.ForbiddenError{}
	}
	scope, err := OrganizationAuthorityScope(b.TenantID, i.OrganizationID, b.UserID)
	if err != nil {
		return err
	}
	var next authority.AuthorityRecord
	if x.Target.Version == 0 {
		next, err = authority.InitializeAuthority(ctx, w, scope, p.service.actor.config.Session.MaximumDuration)
	} else {
		next, err = authority.AdvanceAuthority(ctx, w, scope, x.Target.AuthorizationVersion, p.service.actor.config.Session.MaximumDuration)
	}
	if err != nil {
		return authorityError(err)
	}
	n, err := w.Exec(ctx, `INSERT INTO organization.memberships(tenant_id,organization_id,user_id,role,state,version,authorization_version) VALUES($1,$2,$3,'member','active',$4::numeric,$5::numeric) ON CONFLICT(tenant_id,organization_id,user_id) DO UPDATE SET role='member',state='active',version=EXCLUDED.version,authorization_version=EXCLUDED.authorization_version WHERE organization.memberships.state='removed' AND organization.memberships.version=$6::numeric`, string(b.TenantID), string(i.OrganizationID), string(b.UserID), strconv.FormatUint(x.Target.Version+1, 10), strconv.FormatUint(next.Version, 10), strconv.FormatUint(x.Target.Version, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	n, err = w.Exec(ctx, `UPDATE organization.organizations SET version=version+1,member_count=member_count+1 WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND state='active' AND version<18446744073709551615`, string(b.TenantID), string(i.OrganizationID), strconv.FormatUint(x.Organization.Version, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	n, err = w.Exec(ctx, `UPDATE organization.invitations SET state='accepted',version=version+1,accepted_at=clock_timestamp() WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3 AND state='pending' AND version=$4::numeric AND expires_at>clock_timestamp()`, string(b.TenantID), string(i.OrganizationID), string(i.ID), strconv.FormatUint(i.Version, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return w.RecordOrganizationInvitationMembership(p, kernel.OrganizationInvitationMembership{OrganizationID: string(i.OrganizationID), UserID: b.UserID, BeforeVersion: x.Target.Version, AfterVersion: x.Target.Version + 1})
}
