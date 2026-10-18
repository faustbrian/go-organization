package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// InvitationRecipientIndexMigrationSource adds the exact recipient/verified-ID
// keyset access path. Allocate a later permanent version after installed owner
// migrations and install before selecting ListMine. It changes no rows or old
// migration bytes. PostgreSQL builds concurrently outside a transaction; an
// interrupted/invalid build must be reconciled, never silently skipped.
type InvitationRecipientIndexMigrationSource struct{ Version migrations.Version }

// Load returns one nontransactional forward index migration without IO.
func (s InvitationRecipientIndexMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_invitation_recipient_page", migrations.TransactionModeNone, `CREATE INDEX CONCURRENTLY organization_invitation_recipient_page ON organization.invitations(tenant_id,recipient_user_id,recipient_identifier_id,recipient_identifier_version,invitation_id COLLATE "C");`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
