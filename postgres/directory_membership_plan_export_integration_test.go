//go:build integration

package postgres

// DirectoryMembershipPlanSQL exposes the production statements only to the
// external integration test package, following Go's export_test convention.
func DirectoryMembershipPlanSQL() map[string]string {
	return map[string]string{
		"observe":       observeDirectoryMembershipSQL,
		"owner":         lockDirectoryMembershipOwnerSQL,
		"active":        hasDirectoryMembershipGrantSQL,
		"insert":        insertDirectoryMembershipGrantSQL,
		"update":        updateDirectoryMembershipGrantSQL,
		"require":       requireDirectoryMembershipGrantSQL,
		"remove-member": persistRemovedMemberSQL,
	}
}
