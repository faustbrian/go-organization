package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// InvitationCapabilityMigrationSource adds private original issuance identity
// after InvitationMigrationSource. Existing metadata-only rows remain paired
// NULL and cannot authorize acceptance; no bearer is persisted or backfilled.
// Allocate a permanent later Version. Old readers use explicit column lists.
type InvitationCapabilityMigrationSource struct{ Version migrations.Version }

func (s InvitationCapabilityMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_invitation_original_issuance", migrations.TransactionModeDefault, `ALTER TABLE organization.invitations
 ADD COLUMN capability_envelope bytea,
 ADD COLUMN capability_replay_key_version bigint,
 ADD CONSTRAINT organization_invitation_original_issuance CHECK(
  (capability_envelope IS NULL AND capability_replay_key_version IS NULL) OR
  (capability_envelope IS NOT NULL AND octet_length(capability_envelope)=32 AND capability_envelope<>decode(repeat('00',32),'hex') AND capability_replay_key_version IS NOT NULL AND capability_replay_key_version BETWEEN 1 AND 4294967295)
 );`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
