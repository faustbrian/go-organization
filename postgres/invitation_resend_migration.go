package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// InvitationResendMigrationSource follows InvitationExpiryMigrationSource at
// an unused permanent version, before selecting resend. Existing version1/2
// rows and previous migration bytes remain unchanged. One issued version may
// terminalize once; replacing a pending proof advances only its issued version.
// The original-command delivery ID is immutable history, not a second journal.
type InvitationResendMigrationSource struct{ Version migrations.Version }

func (s InvitationResendMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_invitation_resend", migrations.TransactionModeDefault, `ALTER TABLE organization.invitations
 ADD COLUMN issued_version identity.version NOT NULL DEFAULT 1,
 DROP CONSTRAINT invitations_lifecycle,
 ADD CONSTRAINT invitations_lifecycle CHECK(
  issued_version<18446744073709551615 AND (
  (state='pending' AND version=issued_version AND accepted_at IS NULL AND cancelled_at IS NULL AND rejected_at IS NULL AND expired_at IS NULL AND expiry_reason IS NULL) OR
  (state='accepted' AND version=issued_version+1 AND accepted_at IS NOT NULL AND accepted_at>=created_at AND accepted_at<expires_at AND cancelled_at IS NULL AND rejected_at IS NULL AND expired_at IS NULL AND expiry_reason IS NULL) OR
  (state='cancelled' AND version=issued_version+1 AND accepted_at IS NULL AND cancelled_at IS NOT NULL AND cancelled_at>=created_at AND cancelled_at<expires_at AND rejected_at IS NULL AND expired_at IS NULL AND expiry_reason IS NULL) OR
  (state='rejected' AND version=issued_version+1 AND accepted_at IS NULL AND cancelled_at IS NULL AND rejected_at IS NOT NULL AND rejected_at>=created_at AND rejected_at<expires_at AND expired_at IS NULL AND expiry_reason IS NULL) OR
  (state='expired' AND version=issued_version+1 AND accepted_at IS NULL AND cancelled_at IS NULL AND rejected_at IS NULL AND expired_at IS NOT NULL AND expired_at>=created_at AND expiry_reason IS NOT NULL))
 );
ALTER TABLE organization.command_effects
 ADD COLUMN delivery_effect_id text COLLATE "C",
 ADD CONSTRAINT organization_resend_delivery_scope CHECK(
  (operation='identity.organization.invitation.resend' AND delivery_effect_id IS NOT NULL AND delivery_effect_id ~ '^[0-9a-f]{64}$') OR
  (operation<>'identity.organization.invitation.resend' AND delivery_effect_id IS NULL)),
 DROP CONSTRAINT organization_invitation_effect_scope,
 ADD CONSTRAINT organization_invitation_effect_scope CHECK(
 (operation IN('identity.organization.invitation-send','identity.organization.invitation.accept','identity.organization.invitation.cancel','identity.organization.invitation.reject','identity.organization.invitation.expire','identity.organization.invitation.resend') AND invitation_id IS NOT NULL)
 OR (operation NOT IN('identity.organization.invitation-send','identity.organization.invitation.accept','identity.organization.invitation.cancel','identity.organization.invitation.reject','identity.organization.invitation.expire','identity.organization.invitation.resend') AND invitation_id IS NULL)
 );`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
