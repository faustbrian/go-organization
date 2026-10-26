package postgres

import (
	"context"
	"strings"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OperationLookupTransactionalMigrationSource explicitly selects a blocking,
// transactional build of OperationLookupMigrationSource's exact partial unique
// index. Use it instead of, never after or alongside, the concurrent source at
// the allocated version. Its distinct identity cannot adopt concurrent history.
// PostgreSQL blocks writes during this build: operators must select a bounded
// maintenance window and transaction/lock timeouts before applying it. This is
// suitable for atomic migration commands, not automatic runtime DML activation.
type OperationLookupTransactionalMigrationSource struct{ Version migrations.Version }

// Load preserves the native source's version/context validation and returns one
// detached forward-only transactional migration without IO or mutation.
func (s OperationLookupTransactionalMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	steps, err := (OperationLookupMigrationSource{Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return transactionalIndexMigration(steps[0])
}

// InvitationRecipientIndexTransactionalMigrationSource explicitly selects a
// blocking, transactional build of InvitationRecipientIndexMigrationSource's
// exact recipient keyset index. Choose one source at the allocated version,
// never both variants or a replacement for already installed concurrent history.
// PostgreSQL blocks writes during this build; apply only in an explicit bounded
// operator window with transaction/lock timeouts, not automatic runtime DML.
type InvitationRecipientIndexTransactionalMigrationSource struct{ Version migrations.Version }

// Load preserves the native source's version/context validation and returns one
// detached forward-only transactional migration without IO or mutation.
func (s InvitationRecipientIndexTransactionalMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	steps, err := (InvitationRecipientIndexMigrationSource{Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return transactionalIndexMigration(steps[0])
}

func transactionalIndexMigration(original migrations.Migration) ([]migrations.Migration, error) {
	// Only the two native trusted literals above reach this conversion. Retain
	// every index byte except PostgreSQL's transaction-incompatible keyword; the
	// new name and transaction mode make the alternate checksum explicit.
	step, err := migrations.NewMigration(original.Version(), original.Name()+"_transactional", migrations.TransactionModeDefault, strings.Replace(original.UpSQL(), "CONCURRENTLY ", "", 1), original.DownSQL())
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{step}, nil
}
