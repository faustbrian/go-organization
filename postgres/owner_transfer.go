package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

// PrepareOwnerTransfer freezes current fresh owner admission and both exact
// memberships in the existing keyed command. Execute atomically demotes the
// source to member, promotes the target and advances their scoped authority.
func (s *Service) PrepareOwnerTransfer(ctx context.Context, r organization.OwnerTransferRequest, network string) (PreparedCommand, error) {
	if s == nil || ctx == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	if s.participant.config.OwnerTransferPrimary == nil {
		return PreparedCommand{}, organization.ErrForbidden
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	c, err := s.core.PrepareOwnerTransfer(bounded, r)
	if err != nil {
		return PreparedCommand{}, err
	}
	x, err := c.Input()
	if err != nil {
		return PreparedCommand{}, err
	}
	admission, err := s.participant.config.OwnerTransferPrimary.Prepare(bounded, passwordpg.ActionPrimaryRequest{TenantID: x.Binding.TenantID, TargetSubjectID: x.Binding.UserID, CommandID: x.Binding.CommandID, RecordID: x.Binding.RecordID, Session: x.Bearer, Proof: x.OwnerTransferProof, Caller: s.transferCaller(x.Binding)})
	if err != nil {
		return PreparedCommand{}, storageError(bounded, err)
	}
	// Password/session custody does not establish current MFA policy. This
	// selected SFA profile requires independently known-empty factor state for
	// both subjects; freeze its epochs rather than inferring absence or silently
	// accepting an MFA target under an SFA administrative operation.
	fields := membershipFields(x)
	for _, subject := range []struct {
		user  identity.UserID
		field string
	}{{identity.UserID(x.Binding.ActorID), "action-primary.actor-factor-version"}, {x.Binding.UserID, "action-primary.target-factor-version"}} {
		version, enrolled, err := mfapg.ReadPasswordSigninFactors(bounded, s.participant.repository.pool, x.Binding.TenantID, subject.user, s.config.Core.MaximumDuration)
		if err != nil {
			return PreparedCommand{}, storageError(bounded, err)
		}
		if enrolled || version == 0 {
			return PreparedCommand{}, organization.ErrForbidden
		}
		fields = append(fields, identity.FeatureField{Name: subject.field, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: version}})
	}
	native, err := admission.Command(x.Binding, fields)
	if err != nil {
		return PreparedCommand{}, storageError(bounded, err)
	}
	return s.prepareMapped(bounded, c, native, network)
}

func (s *Service) transferCaller(b identity.CommandBinding) authorization.DecisionContext {
	return transferCaller(b, s.config.Core.Clock.Now())
}

func transferCaller(b identity.CommandBinding, now time.Time) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(b.RecordID)}, Tenant: authorization.TenantID(b.TenantID), Environment: authorization.Environment{Time: now}}}
}

func (p *Contributor) restoreTransfer(ctx context.Context, c nativeCommand, command identity.Command) (passwordpg.ActionPrimaryAdmission, error) {
	if p.config.OwnerTransferPrimary == nil {
		return passwordpg.ActionPrimaryAdmission{}, identity.ForbiddenError{}
	}
	// Restore checks immutable signed originals only. Current session/directory
	// and proof age/consumption remain protected by Admit/Consume/Check in Work.
	return p.config.OwnerTransferPrimary.RestoreCommand(ctx, command, transferCaller(c.spec.Binding, c.originalTime()), session.CSRFToken{})
}

func (c nativeCommand) originalTime() time.Time {
	spec, err := c.original.Bindings()
	if err != nil {
		return time.Time{}
	}
	return spec.IssuedAt
}

// ApplyFeature already holds the native session/directory and tenant fences.
// The organization lock is shared with every member/owner/team transition;
// owner_count never changes, including while the two role rows are replaced.
func (p *Contributor) transferOwner(ctx context.Context, w kernel.Work, c nativeCommand) error {
	b := c.spec.Binding
	var version, state string
	var members, owners int64
	rows, err := w.Query(ctx, `SELECT version::text,state,member_count,owner_count FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 FOR UPDATE`, string(b.TenantID), string(c.org.ID))
	if err = one(rows, err, &version, &state, &members, &owners); err != nil {
		return err
	}
	if state != "active" {
		return identity.ForbiddenError{}
	}
	if version != strconv.FormatUint(c.org.Version, 10) {
		return identity.ConflictError{}
	}
	if members < 2 || owners < 1 || owners >= members {
		return identity.UnavailableError{}
	}
	source, err := readMember(ctx, w, b.TenantID, c.org.ID, identity.UserID(b.ActorID))
	if err != nil {
		return err
	}
	if !source.Active || source.Role != organization.RoleOwner || source.Version != c.actor.Version || source.AuthorizationVersion != c.actor.AuthorizationVersion {
		return identity.ForbiddenError{}
	}
	target, err := readMember(ctx, w, b.TenantID, c.org.ID, b.UserID)
	if err != nil {
		return err
	}
	if !target.Active || !target.Role.Valid() || target.Role == organization.RoleOwner {
		return identity.ForbiddenError{}
	}
	if target.Version != c.target.Version || target.AuthorizationVersion != c.target.AuthorizationVersion || target.Role != c.target.Role {
		return identity.ConflictError{}
	}
	// Both scoped versions change with the role change. Global password/session
	// epochs and independent organization-owned credentials remain untouched (SI-02).
	for _, m := range []organization.Member{source, target} {
		scope, err := OrganizationAuthorityScope(b.TenantID, c.org.ID, m.UserID)
		if err != nil {
			return err
		}
		next, err := authority.AdvanceAuthority(ctx, w, scope, m.AuthorizationVersion, p.config.Session.MaximumDuration)
		if err != nil {
			return authorityError(err)
		}
		role := organization.RoleOwner
		if m.UserID == source.UserID {
			role = organization.RoleMember
		}
		n, err := w.Exec(ctx, `UPDATE organization.memberships SET role=$4,version=version+1,authorization_version=$5::numeric WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND version=$6::numeric AND version<18446744073709551615 AND state='active'`, string(b.TenantID), string(c.org.ID), string(m.UserID), string(role), strconv.FormatUint(next.Version, 10), strconv.FormatUint(m.Version, 10))
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	n, err := w.Exec(ctx, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND version<18446744073709551615 AND state='active' AND owner_count>=1`, string(b.TenantID), string(c.org.ID), version)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
