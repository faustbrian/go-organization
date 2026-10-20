package postgres

import (
	"context"
	"math"
	"strconv"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

func isLifecycleMutation(op organization.Operation) bool {
	return op == organization.Archive || op == organization.Restore
}

// LifecycleMigrationSource follows installed organization migrations, including
// InvitationResendMigrationSource when invitations are installed. It preserves
// child identities and permits truthful system cancellation after natural expiry;
// an archive must not invent a cancellation timestamp before its actual commit.
type LifecycleMigrationSource struct{ Version migrations.Version }

func (s LifecycleMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m, e := migrations.NewMigration(s.Version, "organization_archive_restore", migrations.TransactionModeDefault, lifecycleSQL, "")
	if e != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const lifecycleSQL = `ALTER TABLE organization.organizations
 ADD COLUMN lifecycle_reason text COLLATE "C" CHECK(lifecycle_reason IS NULL OR (octet_length(lifecycle_reason) BETWEEN 1 AND 64 AND lifecycle_reason ~ '^[!-~]+$')),
 ADD COLUMN lifecycle_changed_at timestamptz,
 ADD CONSTRAINT organization_lifecycle_metadata CHECK((lifecycle_reason IS NULL)=(lifecycle_changed_at IS NULL));
DO $lifecycle$ BEGIN
 IF to_regclass('organization.invitations') IS NOT NULL THEN
  ALTER TABLE organization.invitations DROP CONSTRAINT invitations_lifecycle;
  ALTER TABLE organization.invitations ADD CONSTRAINT invitations_lifecycle CHECK(
   issued_version<18446744073709551615 AND (
   (state='pending' AND version=issued_version AND accepted_at IS NULL AND cancelled_at IS NULL AND rejected_at IS NULL AND expired_at IS NULL AND expiry_reason IS NULL) OR
   (state='accepted' AND version=issued_version+1 AND accepted_at IS NOT NULL AND accepted_at>=created_at AND accepted_at<expires_at AND cancelled_at IS NULL AND rejected_at IS NULL AND expired_at IS NULL AND expiry_reason IS NULL) OR
   (state='cancelled' AND version=issued_version+1 AND accepted_at IS NULL AND cancelled_at IS NOT NULL AND cancelled_at>=created_at AND rejected_at IS NULL AND expired_at IS NULL AND expiry_reason IS NULL) OR
   (state='rejected' AND version=issued_version+1 AND accepted_at IS NULL AND cancelled_at IS NULL AND rejected_at IS NOT NULL AND rejected_at>=created_at AND rejected_at<expires_at AND expired_at IS NULL AND expiry_reason IS NULL) OR
   (state='expired' AND version=issued_version+1 AND accepted_at IS NULL AND cancelled_at IS NULL AND rejected_at IS NULL AND expired_at IS NOT NULL AND expired_at>=created_at AND expiry_reason IS NOT NULL))
  );
 END IF;
END $lifecycle$;`

// GetLifecycle is the current owner's narrow active/archived metadata view.
func (s *Service) GetLifecycle(ctx context.Context, r organization.ReadRequest) (organization.View, error) {
	if s == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.core.GetLifecycle(ctx, r)
}

// PrepareArchive authenticates current owner/action proof and freezes one exact
// native command. Execute owns the sole durable state/cancellation transition.
func (s *Service) PrepareArchive(ctx context.Context, r organization.LifecycleRequest, network string) (PreparedCommand, error) {
	return s.prepareLifecycle(ctx, r, network, organization.Archive)
}

// PrepareRestore requires a distinct current action-bound proof, not an archive
// receipt or retained grant. It never recreates terminal child authority.
func (s *Service) PrepareRestore(ctx context.Context, r organization.LifecycleRequest, network string) (PreparedCommand, error) {
	return s.prepareLifecycle(ctx, r, network, organization.Restore)
}

func (p *Contributor) lifecyclePrimary(op organization.Operation) *passwordpg.ActionPrimarySource {
	if p == nil || p.config.Lifecycle.Version != 1 {
		return nil
	}
	if op == organization.Archive {
		return p.config.ArchivePrimary
	}
	if op == organization.Restore {
		return p.config.RestorePrimary
	}
	return nil
}

func (s *Service) prepareLifecycle(ctx context.Context, r organization.LifecycleRequest, network string, op organization.Operation) (PreparedCommand, error) {
	if s == nil || ctx == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	primary := s.participant.lifecyclePrimary(op)
	if primary == nil {
		return PreparedCommand{}, organization.ErrForbidden
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	var c organization.Command
	var e error
	if op == organization.Archive {
		c, e = s.core.PrepareArchive(bounded, r)
	} else {
		c, e = s.core.PrepareRestore(bounded, r)
	}
	if e != nil {
		return PreparedCommand{}, e
	}
	x, e := c.Input()
	if e != nil || x.Lifecycle != s.participant.config.Lifecycle {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	// Self-only primary actions derive their subject from the genuine session;
	// TargetSubjectID belongs exclusively to the separate ownership-transfer API.
	admission, e := primary.Prepare(bounded, passwordpg.ActionPrimaryRequest{TenantID: x.Binding.TenantID, CommandID: x.Binding.CommandID, RecordID: x.Binding.RecordID, Session: x.Bearer, Proof: x.LifecycleProof, Caller: transferCaller(x.Binding, s.config.Core.Clock.Now())})
	if e != nil {
		return PreparedCommand{}, storageError(bounded, e)
	}
	version, enrolled, e := mfapg.ReadPasswordSigninFactors(bounded, s.participant.repository.pool, x.Binding.TenantID, x.Binding.UserID, s.config.Core.MaximumDuration)
	if e != nil {
		return PreparedCommand{}, storageError(bounded, e)
	}
	if enrolled || version == 0 {
		return PreparedCommand{}, organization.ErrForbidden
	}
	fields := append(membershipFields(x), text("lifecycle-state", string(x.LifecycleState)), text("lifecycle-reason", x.LifecycleReason), number("lifecycle-policy-version", x.Lifecycle.Version), identity.FeatureField{Name: "action-primary.actor-factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: version}}, identity.FeatureField{Name: "action-primary.target-factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: version}})
	native, e := admission.Command(x.Binding, fields)
	if e != nil {
		return PreparedCommand{}, storageError(bounded, e)
	}
	return s.prepareMapped(bounded, c, native, network)
}

func (p *Contributor) restoreLifecycle(ctx context.Context, c nativeCommand, command identity.Command) (passwordpg.ActionPrimaryAdmission, error) {
	primary := p.lifecyclePrimary(c.operation)
	if primary == nil {
		return passwordpg.ActionPrimaryAdmission{}, identity.ForbiddenError{}
	}
	return primary.RestoreCommand(ctx, command, transferCaller(c.spec.Binding, c.originalTime()), session.CSRFToken{})
}

func (r *Repository) readLifecycle(ctx context.Context, q organization.Query) (organization.View, error) {
	if !q.Lifecycle || q.Operation != organization.Get && !isLifecycleMutation(q.Operation) || q.TargetID != "" || q.TeamID != "" || q.DynamicRoleID != "" || q.DomainClaimID != "" || q.Limit != 0 || q.Cursor != "" || q.IncludeTeamRoles {
		return organization.View{}, organization.ErrInvalidInput
	}
	v := organization.View{}
	var version, owners, member, epoch string
	e := r.pool.Raw().QueryRow(ctx, `SELECT o.slug,o.name,o.version::text,o.owner_count::text,o.state,coalesce(o.lifecycle_reason,''),a.role,a.version::text,a.authorization_version::text FROM organization.organizations o JOIN organization.memberships a USING(tenant_id,organization_id) WHERE o.tenant_id=$1 AND o.organization_id=$2 AND a.user_id=$3 AND o.state IN('active','archived') AND a.state='active' AND a.role='owner'`, string(q.TenantID), string(q.OrganizationID), string(q.ActorID)).Scan(&v.Organization.Slug, &v.Organization.Name, &version, &owners, &v.LifecycleState, &v.LifecycleReason, &v.Actor.Role, &member, &epoch)
	if e != nil {
		return organization.View{}, storageError(ctx, e)
	}
	v.Organization.ID, v.Organization.TenantID, v.Organization.Active = q.OrganizationID, q.TenantID, v.LifecycleState == organization.LifecycleActive
	v.Actor.OrganizationID, v.Actor.TenantID, v.Actor.UserID, v.Actor.Active = q.OrganizationID, q.TenantID, q.ActorID, true
	if v.Organization.Version, e = positive(version); e != nil {
		return organization.View{}, e
	}
	if v.OwnerCount, e = positive(owners); e != nil {
		return organization.View{}, e
	}
	if v.Actor.Version, e = positive(member); e != nil {
		return organization.View{}, e
	}
	if v.Actor.AuthorizationVersion, e = positive(epoch); e != nil {
		return organization.View{}, e
	}
	return v, ctx.Err()
}

func (p *Contributor) decodeLifecycle(c *nativeCommand, t func(string) string, n func(string) uint64) error {
	expected := organization.LifecycleActive
	if c.operation == organization.Restore {
		expected = organization.LifecycleArchived
	}
	if p.lifecyclePrimary(c.operation) == nil || n("lifecycle-policy-version") != p.config.Lifecycle.Version || t("lifecycle-state") != string(expected) || !validLifecycleCode(t("lifecycle-reason")) || c.org.Version == 0 || c.org.Version == ^uint64(0) || c.actor.Role != organization.RoleOwner || c.actor.Version == 0 || c.actor.AuthorizationVersion == 0 || c.target.Version != 0 || c.target.AuthorizationVersion != 0 || c.target.Role != "" || c.user.Version != 0 || c.user.Status != "" || c.role != "" || string(c.spec.Binding.ActorID) != string(c.spec.Binding.UserID) || c.actorFactorVersion == 0 || c.actorFactorVersion != c.targetFactorVersion {
		return organization.ErrInvalidInput
	}
	c.org.Active = expected == organization.LifecycleActive
	c.lifecycleState = expected
	c.lifecycleReason = t("lifecycle-reason")
	return nil
}

func validLifecycleCode(reason string) bool {
	if len(reason) < 1 || len(reason) > 64 {
		return false
	}
	for _, b := range []byte(reason) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

// The existing tenant/organization lock serializes every native child mutation.
// Advancing this one aggregate epoch establishes denial; child data is retained
// rather than copied into a second authority/cascade engine or fanned out per user.
func (p *Contributor) mutateLifecycle(ctx context.Context, w kernel.Work, c nativeCommand) error {
	b := c.spec.Binding
	var version, state string
	rows, e := w.Query(ctx, `SELECT version::text,state FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 FOR UPDATE`, string(b.TenantID), string(c.org.ID))
	if e = one(rows, e, &version, &state); e != nil {
		return e
	}
	if state != string(c.lifecycleState) || version != strconv.FormatUint(c.org.Version, 10) {
		return identity.ConflictError{}
	}
	owner, e := readMember(ctx, w, b.TenantID, c.org.ID, identity.UserID(b.ActorID))
	if e != nil {
		return e
	}
	if owner != c.actor || !owner.Active || owner.Role != organization.RoleOwner {
		return identity.ForbiddenError{}
	}
	scope, e := OrganizationAuthorityScope(b.TenantID, c.org.ID, owner.UserID)
	if e != nil {
		return e
	}
	if e = authority.RequireAuthority(ctx, w, scope, owner.AuthorizationVersion, p.config.Session.MaximumDuration); e != nil {
		return authorityError(e)
	}
	next := organization.LifecycleArchived
	if c.operation == organization.Restore {
		next = organization.LifecycleActive
	}
	n, e := w.Exec(ctx, `UPDATE organization.organizations SET state=$4,version=version+1,lifecycle_reason=$5,lifecycle_changed_at=clock_timestamp() WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND version<18446744073709551615`, string(b.TenantID), string(c.org.ID), version, string(next), c.lifecycleReason)
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	if c.operation == organization.Archive {
		var installed bool
		rows, e = w.Query(ctx, `SELECT to_regclass('organization.invitations') IS NOT NULL`)
		if e = one(rows, e, &installed); e != nil {
			return e
		}
		if installed {
			// State/version are the invitation owner's existing consumption fence.
			// No capability material is read or changed, and all terminal rows stay
			// untouched. Naturally expired pending rows cancel at real primary time.
			_, e = w.Exec(ctx, `UPDATE organization.invitations SET state='cancelled',version=version+1,cancelled_at=clock_timestamp() WHERE tenant_id=$1 AND organization_id=$2 AND state='pending' AND version=issued_version`, string(b.TenantID), string(c.org.ID))
			if e != nil {
				return e
			}
		}
	}
	return nil
}

func (p *Contributor) checkLifecycleCommit(ctx context.Context, w kernel.Work, c nativeCommand) error {
	expected := organization.LifecycleArchived
	if c.operation == organization.Restore {
		expected = organization.LifecycleActive
	}
	var state, version, reason string
	rows, e := w.Query(ctx, `SELECT state,version::text,lifecycle_reason FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2`, string(c.spec.Binding.TenantID), string(c.org.ID))
	if e = one(rows, e, &state, &version, &reason); e != nil {
		return e
	}
	if state != string(expected) || version != strconv.FormatUint(c.org.Version+1, 10) || reason != c.lifecycleReason {
		return identity.ForbiddenError{}
	}
	owner, e := readMember(ctx, w, c.spec.Binding.TenantID, c.org.ID, identity.UserID(c.spec.Binding.ActorID))
	if e != nil {
		return e
	}
	if owner != c.actor || !owner.Active || owner.Role != organization.RoleOwner {
		return identity.ForbiddenError{}
	}
	return nil
}
