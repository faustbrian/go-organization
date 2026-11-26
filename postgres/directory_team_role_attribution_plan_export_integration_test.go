//go:build integration

package postgres

func DirectoryTeamRoleAttributionPlanSQL() map[string]string {
	return map[string]string{
		"membership":  directoryTeamMembershipSQL,
		"binding":     directoryTeamRoleObservationSQL,
		"attribution": directoryTeamRoleAttributionSQL,
	}
}
