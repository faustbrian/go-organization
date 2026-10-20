package postgres

import (
	"context"
	"errors"
	"strconv"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

func one(rows *kernel.WorkRows, err error, targets ...any) error {
	if err != nil {
		return err
	}
	if rows == nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	if err = rows.Scan(targets...); err != nil {
		return err
	}
	if rows.Next() {
		return identity.UnavailableError{}
	}
	return rows.Err()
}

func (p *Contributor) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if _, _, _, e := w.FeatureScope(p); e != nil {
		return identity.FeatureReceipt{}, e
	}
	c, e := p.decode(command)
	if e != nil {
		return identity.FeatureReceipt{}, e
	}
	var primary passwordpg.ActionPrimaryAdmission
	if c.operation == organization.OwnerTransfer {
		primary, e = p.restoreTransfer(ctx, c, command)
		if e != nil {
			return identity.FeatureReceipt{}, e
		}
	}
	if e = p.admit(ctx, w, c, command, false); e != nil {
		return identity.FeatureReceipt{}, e
	}
	if c.operation == organization.OwnerTransfer {
		if e = primary.Consume(ctx, w, p, command); e != nil {
			return identity.FeatureReceipt{}, e
		}
	}
	b := c.spec.Binding
	// One tenant row serializes cardinality changes as well as organization
	// creation. No user hook, policy callback or external IO occurs under locks.
	// This deliberately coarse first profile makes per-user/per-tenant limits
	// correct across organizations without an unbounded lock/fan-out protocol.
	if _, e = w.Exec(ctx, `INSERT INTO organization.tenant_locks(tenant_id) VALUES($1) ON CONFLICT DO NOTHING`, string(b.TenantID)); e != nil {
		return identity.FeatureReceipt{}, e
	}
	var locked string
	rows, e := w.Query(ctx, `SELECT tenant_id FROM organization.tenant_locks WHERE tenant_id=$1 FOR UPDATE`, string(b.TenantID))
	if e = one(rows, e, &locked); e != nil {
		return identity.FeatureReceipt{}, e
	}
	if c.operation == organization.Create {
		e = p.create(ctx, w, c)
	} else if c.operation == organization.Update {
		e = p.update(ctx, w, c)
	} else if c.operation == organization.OwnerTransfer {
		e = p.transferOwner(ctx, w, c)
	} else if isDynamicRoleMutation(c.operation) {
		e = p.mutateDynamicRole(ctx, w, c)
	} else if isTeamMutation(c.operation) {
		e = p.mutateTeam(ctx, w, c)
	} else if isDomainMutation(c.operation) {
		e = p.mutateDomain(ctx, w, c)
	} else {
		e = p.mutateMember(ctx, w, c)
	}
	if e != nil {
		return identity.FeatureReceipt{}, e
	}
	_, fingerprint, _, e := w.FeatureCommandIdentity(p)
	if e != nil {
		return identity.FeatureReceipt{}, e
	}
	// This retained participant binding is recovery evidence only. The existing
	// identity journal remains the sole command/result and outcome authority.
	if _, e = w.Exec(ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric)`, string(b.CommandID), string(b.TenantID), string(c.org.ID), string(b.UserID), string(b.ActorID), b.OperationID, fingerprint[:], strconv.FormatUint(c.org.Version, 10), strconv.FormatUint(c.org.Version+1, 10)); e != nil {
		return identity.FeatureReceipt{}, e
	}
	return identity.FeatureReceipt{Operation: c.spec.Operation, BeforeVersion: c.org.Version, AfterVersion: c.org.Version + 1}, nil
}

func (p *Contributor) update(ctx context.Context, w kernel.Work, c nativeCommand) error {
	b := c.spec.Binding
	var version, state, name, slug string
	rows, e := w.Query(ctx, `SELECT version::text,state,name,slug FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 FOR UPDATE`, string(b.TenantID), string(c.org.ID))
	if e = one(rows, e, &version, &state, &name, &slug); e != nil {
		return e
	}
	v, e := positive(version)
	if e != nil {
		return e
	}
	if state != "active" {
		return identity.ForbiddenError{}
	}
	if v != c.org.Version {
		return identity.ConflictError{}
	}
	actor, e := readMember(ctx, w, b.TenantID, c.org.ID, identity.UserID(b.ActorID))
	if e != nil {
		return e
	}
	if !actor.Active || actor.Role != c.actor.Role || actor.Version != c.actor.Version || actor.AuthorizationVersion != c.actor.AuthorizationVersion || actor.Role != organization.RoleOwner && actor.Role != organization.RoleAdministrator {
		return identity.ForbiddenError{}
	}
	scope, e := OrganizationAuthorityScope(b.TenantID, c.org.ID, actor.UserID)
	if e != nil {
		return e
	}
	if e = authority.RequireAuthority(ctx, w, scope, actor.AuthorizationVersion, p.config.Session.MaximumDuration); e != nil {
		return authorityError(e)
	}
	// The selected profile rejects identical replacements rather than emitting
	// a fictitious state transition. Tenant serialization also fences the unique
	// slug check against concurrent create/update without changing its scope.
	if name == c.org.Name && slug == c.org.Slug {
		return identity.ConflictError{}
	}
	var duplicate bool
	rows, e = w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM organization.organizations WHERE tenant_id=$1 AND slug=$2 AND organization_id<>$3)`, string(b.TenantID), c.org.Slug, string(c.org.ID))
	if e = one(rows, e, &duplicate); e != nil {
		return e
	}
	if duplicate {
		return identity.ConflictError{}
	}
	// Metadata changes advance the existing aggregate/policy epoch, never a
	// member/global authority or future typed additional fields.
	n, e := w.Exec(ctx, `UPDATE organization.organizations SET name=$4,slug=$5,version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND version<18446744073709551615 AND state='active'`, string(b.TenantID), string(c.org.ID), strconv.FormatUint(c.org.Version, 10), c.org.Name, c.org.Slug)
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *Contributor) create(ctx context.Context, w kernel.Work, c nativeCommand) error {
	b := c.spec.Binding
	var duplicate bool
	rows, e := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM organization.organizations WHERE tenant_id=$1 AND (organization_id=$2 OR slug=$3))`, string(b.TenantID), string(c.org.ID), c.org.Slug)
	if e = one(rows, e, &duplicate); e != nil {
		return e
	}
	if duplicate {
		return identity.ConflictError{}
	}
	var total, memberOf int64
	rows, e = w.Query(ctx, `SELECT (SELECT count(*) FROM organization.organizations WHERE tenant_id=$1),(SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND user_id=$2 AND state='active')`, string(b.TenantID), string(b.UserID))
	if e = one(rows, e, &total, &memberOf); e != nil {
		return e
	}
	if total < 0 || memberOf < 0 {
		return identity.UnavailableError{}
	}
	if uint64(total) >= p.config.MaximumPerTenant || uint64(memberOf) >= p.config.MaximumPerUser {
		// Coordinator.ApplyFeature classifies participant errors before the
		// service sees them. Use its supported denial type: domain-only
		// sentinels would become dependency failures and failed audits.
		return identity.ForbiddenError{}
	}
	if _, e = w.Exec(ctx, `INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count) VALUES($1,$2,$3,$4,'active',1,1,1)`, string(b.TenantID), string(c.org.ID), c.org.Slug, c.org.Name); e != nil {
		return e
	}
	scope, e := OrganizationAuthorityScope(b.TenantID, c.org.ID, b.UserID)
	if e != nil {
		return e
	}
	projection, e := authority.InitializeAuthority(ctx, w, scope, p.config.Session.MaximumDuration)
	if e != nil {
		return authorityError(e)
	}
	_, e = w.Exec(ctx, `INSERT INTO organization.memberships(tenant_id,organization_id,user_id,role,state,version,authorization_version) VALUES($1,$2,$3,'owner','active',1,$4::numeric)`, string(b.TenantID), string(c.org.ID), string(b.UserID), strconv.FormatUint(projection.Version, 10))
	return e
}

func (p *Contributor) mutateMember(ctx context.Context, w kernel.Work, c nativeCommand) error {
	b := c.spec.Binding
	var version, state string
	var members, owners int64
	rows, e := w.Query(ctx, `SELECT version::text,state,member_count,owner_count FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 FOR UPDATE`, string(b.TenantID), string(c.org.ID))
	if e = one(rows, e, &version, &state, &members, &owners); e != nil {
		return e
	}
	v, e := positive(version)
	if e != nil {
		return e
	}
	if state != "active" {
		return identity.ForbiddenError{}
	}
	if v != c.org.Version {
		return identity.ConflictError{}
	}
	if members < 1 || owners < 1 || owners > members {
		return identity.UnavailableError{}
	}
	actor, e := readMember(ctx, w, b.TenantID, c.org.ID, identity.UserID(b.ActorID))
	if e != nil {
		return e
	}
	if !actor.Active || actor.Role != c.actor.Role || actor.Version != c.actor.Version || actor.AuthorizationVersion != c.actor.AuthorizationVersion {
		return identity.ForbiddenError{}
	}
	actorScope, e := OrganizationAuthorityScope(b.TenantID, c.org.ID, actor.UserID)
	if e != nil {
		return e
	}
	if e = authority.RequireAuthority(ctx, w, actorScope, actor.AuthorizationVersion, p.config.Session.MaximumDuration); e != nil {
		return authorityError(e)
	}
	target, e := readMember(ctx, w, b.TenantID, c.org.ID, b.UserID)
	if e != nil {
		return e
	}
	if target.Version != c.target.Version || target.AuthorizationVersion != c.target.AuthorizationVersion || target.Role != c.target.Role {
		return identity.ConflictError{}
	}
	if target.Version == ^uint64(0) {
		return identity.ConflictError{}
	}
	if c.operation == organization.AddMember {
		if target.Active {
			return identity.ConflictError{}
		}
		if uint64(members) >= p.config.MaximumMembers {
			return identity.ForbiddenError{}
		}
		var memberOf int64
		rows, e = w.Query(ctx, `SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, string(b.TenantID), string(b.UserID))
		if e = one(rows, e, &memberOf); e != nil {
			return e
		}
		if memberOf < 0 {
			return identity.UnavailableError{}
		}
		if uint64(memberOf) >= p.config.MaximumPerUser {
			return identity.ForbiddenError{}
		}
	} else {
		if !target.Active {
			return identity.ForbiddenError{}
		}
		if target.Role == organization.RoleOwner && owners < 2 {
			return identity.ForbiddenError{}
		}
	}
	targetScope, e := OrganizationAuthorityScope(b.TenantID, c.org.ID, b.UserID)
	if e != nil {
		return e
	}
	var next authority.AuthorityRecord
	if target.Version == 0 {
		next, e = authority.InitializeAuthority(ctx, w, targetScope, p.config.Session.MaximumDuration)
	} else {
		next, e = authority.AdvanceAuthority(ctx, w, targetScope, target.AuthorizationVersion, p.config.Session.MaximumDuration)
	}
	if e != nil {
		return authorityError(e)
	}
	delta, ownerDelta := int64(1), int64(0)
	if c.operation == organization.AddMember {
		if c.role == organization.RoleOwner {
			ownerDelta = 1
		}
	} else if c.operation == organization.UpdateMember {
		// Owners are the selected static profile's recovery administrators
		// (docs/member-leave.md). The shared aggregate lock/count protects this
		// invariant against role updates, removal, leave and owner transfer.
		delta = 0
		if target.Role == organization.RoleOwner {
			ownerDelta--
		}
		if c.role == organization.RoleOwner {
			ownerDelta++
		}
	} else {
		delta = -1
		if target.Role == organization.RoleOwner {
			ownerDelta = -1
		}
	}
	n, e := w.Exec(ctx, `UPDATE organization.organizations SET version=version+1,member_count=member_count+$4,owner_count=owner_count+$5 WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND version<18446744073709551615 AND member_count+$4>=1 AND owner_count+$5>=1`, string(b.TenantID), string(c.org.ID), strconv.FormatUint(c.org.Version, 10), delta, ownerDelta)
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	if c.operation == organization.AddMember {
		n, e = w.Exec(ctx, `INSERT INTO organization.memberships(tenant_id,organization_id,user_id,role,state,version,authorization_version) VALUES($1,$2,$3,$4,'active',$5::numeric,$6::numeric) ON CONFLICT(tenant_id,organization_id,user_id) DO UPDATE SET role=EXCLUDED.role,state='active',version=EXCLUDED.version,authorization_version=EXCLUDED.authorization_version WHERE organization.memberships.state='removed' AND organization.memberships.version=$7::numeric`, string(b.TenantID), string(c.org.ID), string(b.UserID), string(c.role), strconv.FormatUint(target.Version+1, 10), strconv.FormatUint(next.Version, 10), strconv.FormatUint(target.Version, 10))
	} else if c.operation == organization.UpdateMember {
		n, e = w.Exec(ctx, `UPDATE organization.memberships SET role=$4,version=version+1,authorization_version=$5::numeric WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND version=$6::numeric AND state='active'`, string(b.TenantID), string(c.org.ID), string(b.UserID), string(c.role), strconv.FormatUint(next.Version, 10), strconv.FormatUint(target.Version, 10))
	} else {
		n, e = w.Exec(ctx, `UPDATE organization.memberships SET state='removed',version=version+1,authorization_version=$4::numeric WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND version=$5::numeric AND state='active'`, string(b.TenantID), string(c.org.ID), string(b.UserID), strconv.FormatUint(next.Version, 10), strconv.FormatUint(target.Version, 10))
	}
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func readMember(ctx context.Context, w kernel.Work, tenant identity.TenantID, org organization.ID, user identity.UserID) (organization.Member, error) {
	m := organization.Member{TenantID: tenant, OrganizationID: org, UserID: user}
	rows, e := w.Query(ctx, `SELECT role,version::text,authorization_version::text,state='active' FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 FOR UPDATE`, string(tenant), string(org), string(user))
	if e != nil {
		return m, e
	}
	defer rows.Close()
	if !rows.Next() {
		return m, rows.Err()
	}
	var version, epoch, role string
	if e = rows.Scan(&role, &version, &epoch, &m.Active); e != nil {
		return m, e
	}
	m.Role = organization.Role(role)
	if rows.Next() {
		return m, identity.UnavailableError{}
	}
	if e = rows.Err(); e != nil {
		return m, e
	}
	if m.Version, e = positive(version); e != nil {
		return m, e
	}
	if m.AuthorizationVersion, e = positive(epoch); e != nil {
		return m, e
	}
	return m, nil
}

// RecoverParticipant reads this owner's exact retained effect binding only.
// Absence under the coordinator's recovery fence proves no domain effect;
// committed evidence beside a pending journal is left for the sole coordinator
// to classify as conflicting/unknown, never reconstructed as a fresh success.
func (p *Contributor) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.recoverEffect(ctx, w)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if organization.Operation(b.OperationID) == organization.OwnerTransfer {
		if p.config.OwnerTransferPrimary == nil {
			return kernel.RecoveryUnknown, identity.ForbiddenError{}
		}
		proofStatus, err := p.config.OwnerTransferPrimary.Recover(ctx, w, p)
		if err != nil {
			return kernel.RecoveryUnknown, err
		}
		if proofStatus != status {
			return kernel.RecoveryUnknown, nil
		}
	}
	return status, nil
}

func (p *Contributor) recoverEffect(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, life, e := w.FeatureScope(p)
	if e != nil {
		return kernel.RecoveryUnknown, e
	}
	if p == nil || p.repository == nil || feature.Contributor != p.Descriptor() {
		return kernel.RecoveryUnknown, organization.ErrInvalidInput
	}
	rows, e := w.Query(ctx, `SELECT tenant_id,organization_id,user_id,actor_id,operation,before_version::text,after_version::text FROM organization.command_effects WHERE command_id=$1`, string(b.CommandID))
	if e != nil {
		return kernel.RecoveryUnknown, e
	}
	defer rows.Close()
	if !rows.Next() {
		if e = rows.Err(); e != nil {
			return kernel.RecoveryUnknown, e
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var tenant, org, user, actor, op, before, after string
	if e = rows.Scan(&tenant, &org, &user, &actor, &op, &before, &after); e != nil {
		return kernel.RecoveryUnknown, e
	}
	if rows.Next() {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if e = rows.Err(); e != nil {
		return kernel.RecoveryUnknown, e
	}
	if tenant != string(b.TenantID) || org != b.RecordID || user != string(b.UserID) || actor != string(b.ActorID) || op != b.OperationID || before != strconv.FormatUint(life.BeforeVersion, 10) || after != strconv.FormatUint(life.AfterVersion, 10) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}

func authorityError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	switch err {
	case authority.ErrAuthorityConflict, authority.ErrAuthorityOverflow:
		return identity.ConflictError{}
	case authority.ErrAuthorityDenied:
		return identity.ForbiddenError{}
	}
	return identity.UnavailableError{}
}
