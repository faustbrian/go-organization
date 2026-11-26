package postgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

// DirectoryMembershipObservation describes the exact canonical member and
// the selected connection's contribution for its current incarnation. Zero
// versions mean absence; a nonzero inactive contribution is a tombstone.
// An older incarnation can never prove ownership of the current member.
type DirectoryMembershipObservation struct {
	Member              organization.Member
	ContributionVersion uint64
	ContributionActive  bool
}

const observeDirectoryMembershipSQL = `SELECT COALESCE(m.role,''),COALESCE(m.version::text,'0'),COALESCE(m.authorization_version::text,'0'),COALESCE(m.state='active',false),COALESCE(g.resource_id,''),COALESCE(g.version::text,'0'),COALESCE(g.active,false)
FROM organization.organizations o
LEFT JOIN organization.memberships m ON m.tenant_id=o.tenant_id AND m.organization_id=o.organization_id AND m.user_id=$3
LEFT JOIN organization.directory_membership_grants g ON g.tenant_id=m.tenant_id AND g.organization_id=m.organization_id AND g.user_id=m.user_id AND g.member_version=m.version AND g.provider_id=$4 AND g.connection_id=$5
WHERE o.tenant_id=$1 AND o.organization_id=$2 AND o.state='active'`

// ObserveDirectoryMembership reads trusted storage facts for preparing the
// exact configured SSO child. It grants neither permission nor freshness;
// a current organization observation and the in-Work recheck are still
// required. Keep this bounded primary-only read out of public HTTP. A different
// resource already bound to the connection and member returns conflict.
func (r *Repository) ObserveDirectoryMembership(ctx context.Context, s DirectoryMembershipSource) (DirectoryMembershipObservation, error) {
	return r.observeDirectoryMembership(ctx, s, false)
}

// ObserveManagedSCIMDirectoryMembership reads the current member incarnation
// and only this exact SCIM resource's contribution. Another resource at the
// same connection is absent for this source, not ownership of that resource.
// Zero does not establish historical absence. Preparation grants no authority:
// the original managed delete Work must recheck these facts under owner locks.
func (r *Repository) ObserveManagedSCIMDirectoryMembership(ctx context.Context, s DirectoryMembershipSource) (DirectoryMembershipObservation, error) {
	return r.observeDirectoryMembership(ctx, s, true)
}

func (r *Repository) observeDirectoryMembership(ctx context.Context, s DirectoryMembershipSource, managedSCIM bool) (DirectoryMembershipObservation, error) {
	if r == nil || r.pool == nil || ctx == nil || !s.validate() {
		return DirectoryMembershipObservation{}, organization.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	var role, memberVersion, memberEpoch, resource, contributionVersion string
	var memberActive, contributionActive bool
	err := r.pool.Raw().QueryRow(ctx, observeDirectoryMembershipSQL, string(s.TenantID), string(s.OrganizationID), string(s.UserID), string(s.ProviderID), string(s.ConnectionID)).Scan(&role, &memberVersion, &memberEpoch, &memberActive, &resource, &contributionVersion, &contributionActive)
	if err != nil {
		return DirectoryMembershipObservation{}, storageError(ctx, err)
	}
	if resource != "" && resource != string(s.ResourceID) {
		if !managedSCIM {
			return DirectoryMembershipObservation{}, organization.ErrConflict
		}
		contributionVersion, contributionActive = "0", false
	}
	o := DirectoryMembershipObservation{ContributionActive: contributionActive}
	if memberVersion != "0" {
		o.Member = organization.Member{TenantID: s.TenantID, OrganizationID: s.OrganizationID, UserID: s.UserID, Role: organization.Role(role), Active: memberActive}
		if o.Member.Version, err = positive(memberVersion); err != nil {
			return DirectoryMembershipObservation{}, err
		}
		if o.Member.AuthorizationVersion, err = positive(memberEpoch); err != nil {
			return DirectoryMembershipObservation{}, err
		}
		if !o.Member.Role.Valid() {
			return DirectoryMembershipObservation{}, organization.ErrUnavailable
		}
	}
	if contributionVersion != "0" {
		if o.ContributionVersion, err = positive(contributionVersion); err != nil {
			return DirectoryMembershipObservation{}, err
		}
	}
	return o, nil
}

const (
	hasDirectoryMembershipGrantSQL    = `SELECT EXISTS(SELECT 1 FROM organization.directory_membership_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND member_version=$4::numeric AND active)`
	insertDirectoryMembershipGrantSQL = `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active)
VALUES($1,$2,$3,$4::numeric,$5,$6,$7,$8::numeric,$9) ON CONFLICT DO NOTHING`
	updateDirectoryMembershipGrantSQL  = `UPDATE organization.directory_membership_grants SET version=$8::numeric,active=$9 WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND member_version=$4::numeric AND provider_id=$5 AND connection_id=$6 AND resource_id=$7 AND version=$10::numeric AND active<>$9`
	requireDirectoryMembershipGrantSQL = `SELECT resource_id,version::text,active FROM organization.directory_membership_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND member_version=$4::numeric AND provider_id=$5 AND connection_id=$6`
)

func hasDirectoryMembershipGrant(ctx context.Context, w kernel.Work, s DirectoryMembershipSource, memberVersion uint64) (bool, error) {
	rows, err := w.Query(ctx, hasDirectoryMembershipGrantSQL, string(s.TenantID), string(s.OrganizationID), string(s.UserID), strconv.FormatUint(memberVersion, 10))
	var active bool
	if err := one(rows, err, &active); err != nil {
		return false, err
	}
	return active, nil
}

func persistDirectoryMembershipGrant(ctx context.Context, w kernel.Work, update DirectoryMembershipUpdate, memberVersion uint64) error {
	i, s := update.state.input, update.state.input.Source
	args := []any{string(s.TenantID), string(s.OrganizationID), string(s.UserID), strconv.FormatUint(memberVersion, 10), string(s.ProviderID), string(s.ConnectionID), string(s.ResourceID), strconv.FormatUint(update.AfterVersion(), 10), i.Action == DirectoryMembershipGrant}
	var affected int64
	var err error
	if i.ExpectedVersion == 0 {
		affected, err = w.Exec(ctx, insertDirectoryMembershipGrantSQL, args...)
	} else {
		affected, err = w.Exec(ctx, updateDirectoryMembershipGrantSQL, append(args, strconv.FormatUint(i.ExpectedVersion, 10))...)
	}
	if err != nil {
		return err
	}
	if affected != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func requireDirectoryMembershipGrant(ctx context.Context, w kernel.Work, update DirectoryMembershipUpdate, memberVersion uint64) error {
	i, s := update.state.input, update.state.input.Source
	rows, err := w.Query(ctx, requireDirectoryMembershipGrantSQL, string(s.TenantID), string(s.OrganizationID), string(s.UserID), strconv.FormatUint(memberVersion, 10), string(s.ProviderID), string(s.ConnectionID))
	var resource, version string
	var active bool
	if err := one(rows, err, &resource, &version, &active); err != nil {
		return err
	}
	if resource != string(s.ResourceID) || version != strconv.FormatUint(update.AfterVersion(), 10) || active != (i.Action == DirectoryMembershipGrant) {
		return identity.ForbiddenError{}
	}
	return nil
}
