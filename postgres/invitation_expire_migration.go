package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// InvitationExpiryMigrationSource follows the rejection migration at an unused
// permanent version. It preserves old rows, proof custody and migration bytes.
// Install before enabling explicit expiry; old readers fail closed on the new
// terminal state. Natural expiry remains a pending/version1 projection.
type InvitationExpiryMigrationSource struct{ Version migrations.Version }

// Load returns a forward-only atomic lifecycle extension without IO.
func (s InvitationExpiryMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_invitation_expiry", migrations.TransactionModeDefault, `ALTER TABLE organization.invitations
 ADD COLUMN expired_at timestamptz,
 ADD COLUMN expiry_reason text COLLATE "C" CHECK(expiry_reason IS NULL OR octet_length(expiry_reason) BETWEEN 1 AND 64),
 DROP CONSTRAINT invitations_state_check,
 DROP CONSTRAINT invitations_lifecycle,
 ADD CONSTRAINT invitations_state_check CHECK(state IN('pending','accepted','cancelled','rejected','expired')),
 ADD CONSTRAINT invitations_lifecycle CHECK(
  (state='pending' AND version=1 AND accepted_at IS NULL AND cancelled_at IS NULL AND rejected_at IS NULL AND expired_at IS NULL AND expiry_reason IS NULL) OR
  (state='accepted' AND version=2 AND accepted_at IS NOT NULL AND accepted_at>=created_at AND accepted_at<expires_at AND cancelled_at IS NULL AND rejected_at IS NULL AND expired_at IS NULL AND expiry_reason IS NULL) OR
  (state='cancelled' AND version=2 AND accepted_at IS NULL AND cancelled_at IS NOT NULL AND cancelled_at>=created_at AND cancelled_at<expires_at AND rejected_at IS NULL AND expired_at IS NULL AND expiry_reason IS NULL) OR
  (state='rejected' AND version=2 AND accepted_at IS NULL AND cancelled_at IS NULL AND rejected_at IS NOT NULL AND rejected_at>=created_at AND rejected_at<expires_at AND expired_at IS NULL AND expiry_reason IS NULL) OR
  (state='expired' AND version=2 AND accepted_at IS NULL AND cancelled_at IS NULL AND rejected_at IS NULL AND expired_at IS NOT NULL AND expired_at>=created_at AND expiry_reason IS NOT NULL)
 );
ALTER TABLE organization.command_effects DROP CONSTRAINT organization_invitation_effect_scope;
ALTER TABLE organization.command_effects ADD CONSTRAINT organization_invitation_effect_scope CHECK(
 (operation IN('identity.organization.invitation-send','identity.organization.invitation.accept','identity.organization.invitation.cancel','identity.organization.invitation.reject','identity.organization.invitation.expire') AND invitation_id IS NOT NULL)
 OR (operation NOT IN('identity.organization.invitation-send','identity.organization.invitation.accept','identity.organization.invitation.cancel','identity.organization.invitation.reject','identity.organization.invitation.expire') AND invitation_id IS NULL)
);`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
