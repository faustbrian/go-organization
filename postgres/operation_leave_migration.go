package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// LeaveOperationLookupMigrationSource installs the exact-epoch natural self-
// leave lookup. Allocate a new version, or use a separate migration namespace;
// do not insert this step into previously installed invitation history. The
// existing organization lock permits only one committed leave per epoch. This
// partial unique index adds one narrow index entry per committed leave, not a
// new journal. Concurrent builds run outside transactions; interrupted/invalid
// indexes require explicit operator reconciliation before enabling the facade.
type LeaveOperationLookupMigrationSource struct{ Version migrations.Version }

// Load returns a detached forward-only concurrent index migration without IO.
func (s LeaveOperationLookupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "organization_leave_operation_lookup", migrations.TransactionModeNone, `CREATE UNIQUE INDEX CONCURRENTLY organization_repeat_leave ON organization.command_effects(tenant_id,organization_id,before_version) WHERE operation='identity.organization.member.leave';`, "")
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	return []migrations.Migration{step}, nil
}

// LeaveOperationLookupTransactionalMigrationSource selects a blocking atomic
// build of the same partial index instead of the concurrent source, never after
// or alongside it. Its distinct checksum cannot adopt concurrent history.
// Select bounded transaction/lock timeouts and a maintenance window: PostgreSQL
// blocks command-effect writes during this build. It is not runtime DML setup.
type LeaveOperationLookupTransactionalMigrationSource struct{ Version migrations.Version }

// Load preserves native version/context validation and the exact index shape.
func (s LeaveOperationLookupTransactionalMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	steps, err := (LeaveOperationLookupMigrationSource{Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return transactionalIndexMigration(steps[0])
}
