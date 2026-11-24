package postgres

import (
	"context"
	"strconv"

	organization "github.com/faustbrian/go-organization"
)

// DirectoryTeamMembershipObservation is an attributed record-local projection.
// Local is the current local grant; Source is only this named source row bound
// to the current organization membership epoch. Neither bit grants permission
// or proves provider/connection/generation validity. Version is the retained
// source epoch (zero for absence); all other versions describe current targets.
type DirectoryTeamMembershipObservation struct {
	Local, Source                             bool
	Version                                   uint64
	OrganizationVersion, CredentialVersion    uint64
	MemberVersion, MemberAuthorizationVersion uint64
	TeamVersion, UserVersion                  uint64
}

// ObserveDirectoryTeamMembership reads one exact source and local grant from
// the primary, requiring an active org/member/user and live retained team ID.
// This trusted persistence API performs no independent user authorization and
// must not be exposed directly to HTTP. SSO must separately admit the caller and
// current external source. No default team read or role query includes Source.
// Missing source rows return Version zero; missing/foreign targets deny with a
// zero projection. Reads are bounded, uncached and do not retain snapshot locks.
func (r *Repository) ObserveDirectoryTeamMembership(ctx context.Context, s DirectoryTeamGrantScope) (DirectoryTeamMembershipObservation, error) {
	if r == nil || r.pool == nil || ctx == nil || !s.validate() {
		return DirectoryTeamMembershipObservation{}, organization.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	var result DirectoryTeamMembershipObservation
	var source, org, credential, member, authorizationVersion, team, user string
	err := r.pool.Raw().QueryRow(ctx, directoryTeamMembershipSQL, string(s.TenantID), string(s.OrganizationID), string(s.ProviderID), string(s.ConnectionID), string(s.GroupID), string(s.TeamID), string(s.UserID)).Scan(&result.Local, &result.Source, &source, &org, &credential, &member, &authorizationVersion, &team, &user)
	if err != nil {
		return DirectoryTeamMembershipObservation{}, storageError(ctx, err)
	}
	result.Version, err = strconv.ParseUint(source, 10, 64)
	if err != nil || strconv.FormatUint(result.Version, 10) != source {
		return DirectoryTeamMembershipObservation{}, organization.ErrUnavailable
	}
	for _, item := range []struct {
		raw    string
		target *uint64
	}{{org, &result.OrganizationVersion}, {credential, &result.CredentialVersion}, {member, &result.MemberVersion}, {authorizationVersion, &result.MemberAuthorizationVersion}, {team, &result.TeamVersion}, {user, &result.UserVersion}} {
		*item.target, err = positive(item.raw)
		if err != nil {
			return DirectoryTeamMembershipObservation{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return DirectoryTeamMembershipObservation{}, err
	}
	return result, nil
}

const directoryTeamMembershipSQL = `SELECT
 EXISTS(SELECT 1 FROM organization.team_memberships local WHERE local.tenant_id=m.tenant_id AND local.organization_id=m.organization_id AND local.team_id=t.team_id AND local.user_id=m.user_id AND local.state='active' AND local.organization_member_version=m.version),
 coalesce(g.active AND g.organization_member_version=m.version,false),coalesce(g.version::text,'0'),
 o.version::text,o.credential_version::text,m.version::text,m.authorization_version::text,t.version::text,u.version::text
FROM organization.organizations o
JOIN organization.memberships m USING(tenant_id,organization_id)
JOIN organization.teams t USING(tenant_id,organization_id)
JOIN organization.team_identities ti USING(tenant_id,organization_id,team_id)
JOIN identity.users u ON u.tenant_id=m.tenant_id AND u.user_id=m.user_id
LEFT JOIN organization.directory_team_grants g ON g.tenant_id=m.tenant_id AND g.organization_id=m.organization_id AND g.user_id=m.user_id AND g.team_id=t.team_id AND g.provider_id=$3 AND g.connection_id=$4 AND g.group_id=$5
WHERE o.tenant_id=$1 AND o.organization_id=$2 AND t.team_id=$6 AND m.user_id=$7
AND o.state='active' AND m.state='active' AND u.status='active' AND ti.deleted_version IS NULL`
