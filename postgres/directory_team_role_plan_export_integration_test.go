//go:build integration

package postgres

func DirectoryTeamRolePlanSQL() map[string]string {
	return map[string]string{
		"candidates": directoryTeamRoleCandidatesSQL,
		"capacity":   directoryTeamRoleCapacitySQL,
		"selection":  directoryTeamRoleSelectionSQL,
		"row":        directoryTeamRoleRowSQL,
		"lock":       lockDirectoryTeamRoleOrganizationSQL,
		"upsert":     upsertDirectoryTeamRoleSQL,
		"delete":     deleteDirectoryTeamRoleSQL,
		"epoch":      advanceDirectoryTeamRoleOrganizationSQL,
		"effective":  effectiveDirectoryTeamRolesSQL,
		"federated":  effectiveProviderDirectoryTeamRolesSQL,
	}
}
