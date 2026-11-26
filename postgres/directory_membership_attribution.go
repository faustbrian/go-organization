package postgres

import (
	"context"

	organization "github.com/faustbrian/go-organization"
)

// DirectoryMembershipAttribution combines the existing exact-source membership
// projection with its active organization's aggregate and credential versions.
// Local means an active member has no active directory contribution in its
// current incarnation; OtherSource means an active member has an active
// contribution from another provider or connection in that incarnation. Neither
// flag confers authority.
type DirectoryMembershipAttribution struct {
	Membership          DirectoryMembershipObservation
	OrganizationVersion uint64
	CredentialVersion   uint64
	Local               bool
	OtherSource         bool
}

const observeDirectoryMembershipAttributionSQL = `SELECT COALESCE(m.role,''),COALESCE(m.version::text,'0'),COALESCE(m.authorization_version::text,'0'),COALESCE(m.state='active',false),COALESCE(g.resource_id,''),COALESCE(g.version::text,'0'),COALESCE(g.active,false),o.version::text,o.credential_version::text,
COALESCE(m.state='active',false) AND EXISTS(
 SELECT 1 FROM organization.directory_membership_grants other_source
 WHERE other_source.tenant_id=m.tenant_id AND other_source.organization_id=m.organization_id AND other_source.user_id=m.user_id
 AND other_source.member_version=m.version AND other_source.active
 AND (other_source.provider_id<>$4 OR other_source.connection_id<>$5))
FROM organization.organizations o
LEFT JOIN organization.memberships m ON m.tenant_id=o.tenant_id AND m.organization_id=o.organization_id AND m.user_id=$3
LEFT JOIN organization.directory_membership_grants g ON g.tenant_id=m.tenant_id AND g.organization_id=m.organization_id AND g.user_id=m.user_id AND g.member_version=m.version AND g.provider_id=$4 AND g.connection_id=$5
WHERE o.tenant_id=$1 AND o.organization_id=$2 AND o.state='active'`

// ObserveDirectoryMembershipAttribution reads the exact member, source and
// active owner versions in one primary snapshot, within the repository's read
// budget. Like ObserveDirectoryMembership, it neither authenticates nor grants
// permission or freshness; consumers must separately authorize and recheck their
// scope and authority. Protected writes retain their own in-Work fences.
// Retired or future member incarnations cannot establish current origin. A
// resource rebound returns organization.ErrConflict and a zero projection;
// every other failure also returns a zero projection. No state is changed.
func (r *Repository) ObserveDirectoryMembershipAttribution(ctx context.Context, s DirectoryMembershipSource) (DirectoryMembershipAttribution, error) {
	if r == nil || r.pool == nil || ctx == nil || !s.validate() {
		return DirectoryMembershipAttribution{}, organization.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	var role, memberVersion, memberEpoch, resource, contributionVersion, ownerVersion, credentialVersion string
	var memberActive, contributionActive, otherSource bool
	err := r.pool.Raw().QueryRow(ctx, observeDirectoryMembershipAttributionSQL, string(s.TenantID), string(s.OrganizationID), string(s.UserID), string(s.ProviderID), string(s.ConnectionID)).Scan(&role, &memberVersion, &memberEpoch, &memberActive, &resource, &contributionVersion, &contributionActive, &ownerVersion, &credentialVersion, &otherSource)
	if err != nil {
		return DirectoryMembershipAttribution{}, storageError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return DirectoryMembershipAttribution{}, err
	}
	if resource != "" && resource != string(s.ResourceID) {
		return DirectoryMembershipAttribution{}, organization.ErrConflict
	}
	observed := DirectoryMembershipAttribution{
		Membership:  DirectoryMembershipObservation{ContributionActive: contributionActive},
		Local:       memberActive && !contributionActive && !otherSource,
		OtherSource: otherSource,
	}
	if observed.OrganizationVersion, err = positive(ownerVersion); err != nil {
		return DirectoryMembershipAttribution{}, err
	}
	if observed.CredentialVersion, err = positive(credentialVersion); err != nil {
		return DirectoryMembershipAttribution{}, err
	}
	if memberVersion != "0" {
		member := organization.Member{TenantID: s.TenantID, OrganizationID: s.OrganizationID, UserID: s.UserID, Role: organization.Role(role), Active: memberActive}
		if member.Version, err = positive(memberVersion); err != nil {
			return DirectoryMembershipAttribution{}, err
		}
		if member.AuthorizationVersion, err = positive(memberEpoch); err != nil {
			return DirectoryMembershipAttribution{}, err
		}
		if !member.Role.Valid() {
			return DirectoryMembershipAttribution{}, organization.ErrUnavailable
		}
		observed.Membership.Member = member
	}
	if contributionVersion != "0" {
		if observed.Membership.ContributionVersion, err = positive(contributionVersion); err != nil {
			return DirectoryMembershipAttribution{}, err
		}
	}
	return observed, nil
}
