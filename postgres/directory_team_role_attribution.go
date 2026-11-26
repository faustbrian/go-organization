package postgres

import (
	"context"

	organization "github.com/faustbrian/go-organization"
)

// DirectoryTeamRoleAttribution separates current native membership and role
// epochs from the exact source's retained role record. CurrentRoleVersion and
// CurrentBindingVersion are zero independently when not active (an active
// binding also requires an active requested role). A zero RetainedGrantVersion
// means no role record exists for the selected source. A retained record may
// refer to an older grant or binding, a different role or member resource, or
// stale external provider evidence. It does not establish effective access.
type DirectoryTeamRoleAttribution struct {
	Membership                                   DirectoryTeamMembershipObservation
	CurrentBindingVersion, CurrentRoleVersion    uint64
	Retained                                     DirectoryTeamRoleSource
	RetainedGrantVersion, RetainedBindingVersion uint64
}

// ObserveDirectoryTeamRoleAttribution reads an exact source, local membership,
// requested active role, and optional active binding in one bounded primary
// snapshot. Missing, foreign or inactive organization/member/user/team targets
// return a zero projection and ErrForbidden; invalid inputs return a zero
// projection and ErrInvalidInput. Missing or inactive roles do not erase the
// independently retained source record. The read neither validates external
// authority nor admits a caller, grants permission, mutates state, or retains
// locks. Do not expose it directly to HTTP or use it in place of a Work fence.
func (r *Repository) ObserveDirectoryTeamRoleAttribution(ctx context.Context, s DirectoryTeamGrantScope, roleID organization.ID) (DirectoryTeamRoleAttribution, error) {
	if r == nil || r.pool == nil || ctx == nil || !s.validate() || !scope(string(roleID)) {
		return DirectoryTeamRoleAttribution{}, organization.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()

	var result DirectoryTeamRoleAttribution
	member := &result.Membership
	var sourceVersion, orgVersion, credentialVersion, memberVersion, authorizationVersion, teamVersion, userVersion string
	var bindingVersion, roleVersion, resourceID, retainedRoleID, grantVersion, retainedBinding, providerVersion, mappingVersion, connectionVersion string
	var hasRetained bool
	err := r.pool.Raw().QueryRow(ctx, directoryTeamRoleAttributionSQL,
		string(s.TenantID), string(s.OrganizationID), string(s.ProviderID), string(s.ConnectionID),
		string(s.GroupID), string(s.TeamID), string(s.UserID), string(roleID),
	).Scan(
		&member.Local, &member.Source, &sourceVersion, &orgVersion, &credentialVersion, &memberVersion,
		&authorizationVersion, &teamVersion, &userVersion, &bindingVersion, &roleVersion, &hasRetained,
		&resourceID, &retainedRoleID, &grantVersion, &retainedBinding, &providerVersion, &mappingVersion, &connectionVersion,
	)
	if err != nil {
		return DirectoryTeamRoleAttribution{}, storageError(ctx, err)
	}

	for _, version := range []struct {
		raw      string
		target   *uint64
		optional bool
	}{
		{raw: sourceVersion, target: &member.Version, optional: true},
		{raw: orgVersion, target: &member.OrganizationVersion},
		{raw: credentialVersion, target: &member.CredentialVersion},
		{raw: memberVersion, target: &member.MemberVersion},
		{raw: authorizationVersion, target: &member.MemberAuthorizationVersion},
		{raw: teamVersion, target: &member.TeamVersion},
		{raw: userVersion, target: &member.UserVersion},
		{raw: bindingVersion, target: &result.CurrentBindingVersion, optional: true},
		{raw: roleVersion, target: &result.CurrentRoleVersion, optional: true},
	} {
		if version.optional && version.raw == "0" {
			continue
		}
		*version.target, err = positive(version.raw)
		if err != nil {
			return DirectoryTeamRoleAttribution{}, err
		}
	}
	if hasRetained {
		if !scope(resourceID) || !scope(retainedRoleID) {
			return DirectoryTeamRoleAttribution{}, organization.ErrUnavailable
		}
		result.Retained = DirectoryTeamRoleSource{
			Scope: s, MemberResourceID: organization.ID(resourceID), RoleID: organization.ID(retainedRoleID),
		}
		for _, version := range []struct {
			raw    string
			target *uint64
		}{
			{grantVersion, &result.RetainedGrantVersion}, {retainedBinding, &result.RetainedBindingVersion},
			{providerVersion, &result.Retained.ProviderVersion}, {mappingVersion, &result.Retained.MappingVersion},
			{connectionVersion, &result.Retained.ConnectionVersion},
		} {
			*version.target, err = positive(version.raw)
			if err != nil {
				return DirectoryTeamRoleAttribution{}, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return DirectoryTeamRoleAttribution{}, err
	}
	return result, nil
}

// The retained record belongs to the source grant key, not to the requested
// role or the current grant/member/binding epochs; drift compares them later.
const directoryTeamRoleAttributionSQL = `SELECT
 EXISTS(SELECT 1 FROM organization.team_memberships local WHERE local.tenant_id=m.tenant_id AND local.organization_id=m.organization_id AND local.team_id=t.team_id AND local.user_id=m.user_id AND local.state='active' AND local.organization_member_version=m.version),
 coalesce(g.active AND g.organization_member_version=m.version,false),coalesce(g.version::text,'0'),
 o.version::text,o.credential_version::text,m.version::text,m.authorization_version::text,t.version::text,u.version::text,
 coalesce(b.version::text,'0'),coalesce(cr.version::text,'0'),d.user_id IS NOT NULL,
 coalesce(d.member_resource_id::text,''),coalesce(d.role_id::text,''),coalesce(d.grant_version::text,''),coalesce(d.binding_version::text,''),
 coalesce(d.provider_version::text,''),coalesce(d.mapping_version::text,''),coalesce(d.connection_version::text,'')
FROM organization.organizations o
JOIN organization.memberships m USING(tenant_id,organization_id)
JOIN organization.teams t USING(tenant_id,organization_id)
JOIN organization.team_identities ti USING(tenant_id,organization_id,team_id)
JOIN identity.users u ON u.tenant_id=m.tenant_id AND u.user_id=m.user_id
LEFT JOIN organization.directory_team_grants g ON g.tenant_id=m.tenant_id AND g.organization_id=m.organization_id AND g.user_id=m.user_id AND g.team_id=t.team_id AND g.provider_id=$3 AND g.connection_id=$4 AND g.group_id=$5
LEFT JOIN organization.custom_roles cr ON cr.tenant_id=o.tenant_id AND cr.organization_id=o.organization_id AND cr.role_id=$8 AND cr.state='active'
LEFT JOIN organization.team_role_bindings b ON b.tenant_id=t.tenant_id AND b.organization_id=t.organization_id AND b.team_id=t.team_id AND b.role_id=$8 AND b.state='active' AND cr.role_id IS NOT NULL
LEFT JOIN organization.directory_team_role_grants d ON d.tenant_id=g.tenant_id AND d.organization_id=g.organization_id AND d.user_id=g.user_id AND d.team_id=g.team_id AND d.provider_id=g.provider_id AND d.connection_id=g.connection_id AND d.group_id=g.group_id
WHERE o.tenant_id=$1 AND o.organization_id=$2 AND t.team_id=$6 AND m.user_id=$7
AND o.state='active' AND m.state='active' AND u.status='active' AND ti.deleted_version IS NULL`
