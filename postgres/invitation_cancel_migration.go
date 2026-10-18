package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// InvitationCancellationMigrationSource extends the installed invitation
// lifecycle without rewriting either prior migration. Allocate a permanent
// later version after all installed organization migrations. Existing pending
// and accepted rows retain their exact identity, proof custody and versions.
type InvitationCancellationMigrationSource struct{ Version migrations.Version }

// Load returns one forward migration, honoring cancellation without IO.
func (s InvitationCancellationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_invitation_cancellation", migrations.TransactionModeDefault, `ALTER TABLE organization.invitations
 ADD COLUMN cancelled_at timestamptz,
 DROP CONSTRAINT invitations_state_check,
 DROP CONSTRAINT invitations_check,
 ADD CONSTRAINT invitations_state_check CHECK(state IN('pending','accepted','cancelled')),
 ADD CONSTRAINT invitations_lifecycle CHECK(
  (state='pending' AND version=1 AND accepted_at IS NULL AND cancelled_at IS NULL) OR
  (state='accepted' AND version=2 AND accepted_at IS NOT NULL AND accepted_at>=created_at AND accepted_at<expires_at AND cancelled_at IS NULL) OR
  (state='cancelled' AND version=2 AND accepted_at IS NULL AND cancelled_at IS NOT NULL AND cancelled_at>=created_at AND cancelled_at<expires_at)
 );
ALTER TABLE organization.command_effects DROP CONSTRAINT command_effects_check1;
ALTER TABLE organization.command_effects ADD CONSTRAINT organization_invitation_effect_scope CHECK(
 (operation IN('identity.organization.invitation-send','identity.organization.invitation.accept','identity.organization.invitation.cancel') AND invitation_id IS NOT NULL)
 OR (operation NOT IN('identity.organization.invitation-send','identity.organization.invitation.accept','identity.organization.invitation.cancel') AND invitation_id IS NULL)
);`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
