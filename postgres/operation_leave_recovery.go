package postgres

import (
	"context"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

// Only the operation facade opts into self-history disclosure without current
// membership. The legacy Service.Recover membership admission is unchanged.
// This snapshot is an admission fence, not another history/result authority.
type leaveRecoveryAdmission struct {
	organizationVersion, memberVersion, authorityVersion uint64
	role                                                 organization.Role
	active                                               bool
}

func (s *Service) leaveRecoveryAdmission(ctx context.Context, b identity.CommandBinding) (leaveRecoveryAdmission, error) {
	var a leaveRecoveryAdmission
	var epoch, member, auth string
	err := s.participant.repository.pool.Raw().QueryRow(ctx, `SELECT o.version::text,m.version::text,m.authorization_version::text,m.role,m.state='active'
FROM organization.organizations o JOIN organization.memberships m USING(tenant_id,organization_id)
WHERE o.tenant_id=$1 AND o.organization_id=$2 AND m.user_id=$3 AND o.state='active'`, string(b.TenantID), b.RecordID, string(b.UserID)).Scan(&epoch, &member, &auth, &a.role, &a.active)
	if err != nil {
		return a, storageError(ctx, err)
	}
	if a.organizationVersion, err = positive(epoch); err != nil {
		return a, err
	}
	if a.memberVersion, err = positive(member); err != nil {
		return a, err
	}
	if a.authorityVersion, err = positive(auth); err != nil {
		return a, err
	}
	return a, nil
}

func (s *Service) revalidateLeaveRecovery(ctx context.Context, b identity.CommandBinding, admitted leaveRecoveryAdmission) error {
	current, err := s.leaveRecoveryAdmission(ctx, b)
	if err != nil {
		return err
	}
	if current != admitted {
		return organization.ErrForbidden
	}
	scope, err := OrganizationAuthorityScope(b.TenantID, organization.ID(b.RecordID), b.UserID)
	if err != nil {
		return err
	}
	store, err := authority.NewAuthorityStore(s.participant.repository.pool.Raw(), s.participant.repository.maximum)
	if err != nil {
		return organization.ErrUnavailable
	}
	live, err := store.Get(ctx, scope)
	if err != nil {
		return publicTeamAuthorityError(err)
	}
	if live.Version != current.authorityVersion {
		return organization.ErrForbidden
	}
	return nil
}

func (s *Service) recoverLeaveOperation(ctx context.Context, a organization.Authentication, b identity.CommandBinding, departed bool) (out organization.StoreResult, err error) {
	if ctx == nil || s == nil {
		return out, organization.ErrInvalidInput
	}
	defer func() {
		if recover() != nil {
			out, err = organization.StoreResult{}, organization.ErrUnavailable
		}
	}()
	if b.OperationID != string(organization.LeaveMember) || b.ValidateFor(organization.LeaveMember.Descriptor()) != nil || b.ActorKind != authorization.SubjectUser || b.UserID != identity.UserID(b.ActorID) || b.TenantID != a.TenantID || b.PolicyID != s.config.Core.PolicyID || b.PolicyVersion != s.config.Core.PolicyVersion {
		return out, organization.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	token, err := session.ParseToken(a.Bearer.Token())
	if err != nil {
		return out, organization.ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return out, organization.ErrForbidden
	}
	observed, err := s.config.Sessions.Get(ctx, session.GetRequest{TenantID: a.TenantID, Credential: credential})
	if err != nil {
		return out, storageError(ctx, err)
	}
	if observed.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return out, organization.ErrForbidden
	}
	bound, err := observed.Session.Bindings()
	if err != nil || bound.UserID != b.UserID || bound.TenantID != b.TenantID {
		return out, organization.ErrForbidden
	}
	if _, _, _, err = sessionpg.OriginalSessionAdmission(s.participant.config.Profile, observed.Session, b); err != nil {
		return out, organization.ErrForbidden
	}
	admitted, err := s.leaveRecoveryAdmission(ctx, b)
	if err != nil {
		return out, err
	}
	if departed && admitted.active {
		return out, organization.ErrConflict
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Core.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(b.RecordID), Attributes: authorization.Attributes{"organization.policy-version": authorization.StringValue(strconv.FormatUint(admitted.organizationVersion, 10))}}, Environment: authorization.Environment{Time: s.config.Core.Clock.Now()}}}
	decision, err := s.config.Authorization.Decide(ctx, caller)
	if err != nil {
		return out, storageError(ctx, err)
	}
	if decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return out, organization.ErrForbidden
	}
	// The kernel still applies its explicit current command-query policy. It
	// returns only exact historical metadata, not a membership or mutation grant.
	queryCaller := caller
	queryCaller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
	r := &recoveryInput{binding: b, caller: queryCaller, observed: observed, credential: credential, leave: &admitted}
	u := &unitOfWork{service: s, recovery: r}
	out, err = u.Recover(ctx, b.CommandID)
	if out.Receipt.Outcome == identity.CommitOutcomeInvalid {
		return out, err
	}
	// A query-policy callback can withdraw the selected self-history policy
	// after initial admission. Decide once more at the return boundary, then
	// fence its own callbacks against the original (not renewed) observation.
	caller.Request.Environment.Time = s.config.Core.Clock.Now()
	decision, policyErr := s.config.Authorization.Decide(ctx, caller)
	if policyErr != nil {
		return organization.StoreResult{}, storageError(ctx, policyErr)
	}
	if decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	if revalidationErr := s.revalidateRecovery(ctx, r); revalidationErr != nil {
		return organization.StoreResult{}, revalidationErr
	}
	return out, err
}
