package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// OperationLookupMigrationSource appends the natural repeat-removal access path
// to existing installed organization history without changing its checksums.
// The native organization epoch lock already permits at most one committed
// removal per tenant/org/before-version; this partial unique index makes that
// lookup bounded without indexing unrelated command effects. Install the later
// allocated version before enabling the facade. The concurrent build runs
// outside transactions; interrupted/invalid builds need explicit reconciliation.
// No destructive down migration or new command/result authority is introduced.
type OperationLookupMigrationSource struct {
	Version migrations.Version
}

// Load returns one detached forward-only nontransactional index migration.
// Nil/cancelled context and invalid versions fail without IO or mutation.
func (s OperationLookupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "organization_operation_lookup", migrations.TransactionModeNone, `CREATE UNIQUE INDEX CONCURRENTLY organization_repeat_removal ON organization.command_effects(tenant_id,organization_id,before_version) WHERE operation='identity.organization.member.remove';`, "")
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	return []migrations.Migration{step}, nil
}
