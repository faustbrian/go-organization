package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// InvitationMigrationSource adds only the selected existing-recipient,
// member-grant invitation profile. Allocate Version permanently after this
// owner's original membership migration and the shared delivery migrations.
// The original migration remains byte-for-byte unchanged for installed users.
type InvitationMigrationSource struct{ Version migrations.Version }

func (s InvitationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_invitations", migrations.TransactionModeDefault, invitationSchemaSQL, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// Identifier IDs/versions are retained historical fences, not foreign-key
// liveness. The identity owner may revoke/remove that address; native recipient
// admission must then reject acceptance rather than block address removal.
const invitationSchemaSQL = `CREATE TABLE organization.invitations(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 invitation_id identity.directory_id NOT NULL,
 recipient_user_id identity.directory_id NOT NULL,
 recipient_identifier_id identity.directory_id NOT NULL,
 recipient_identifier_version identity.version NOT NULL,
 created_by identity.directory_id NOT NULL,
 role text NOT NULL CHECK(role='member'),
 state text NOT NULL CHECK(state IN('pending','accepted')),
 version identity.version NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 accepted_at timestamptz,
 delivery_effect_id text COLLATE "C" NOT NULL CHECK(delivery_effect_id ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,invitation_id),
 FOREIGN KEY(tenant_id,organization_id) REFERENCES organization.organizations(tenant_id,organization_id),
 FOREIGN KEY(tenant_id,recipient_user_id) REFERENCES identity.users(tenant_id,user_id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES identity.users(tenant_id,user_id),
 CHECK((state='pending' AND version=1 AND accepted_at IS NULL) OR
       (state='accepted' AND version=2 AND accepted_at IS NOT NULL AND accepted_at>=created_at AND accepted_at<expires_at)),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '720 hours'
       AND date_trunc('second',expires_at)=expires_at)
);
CREATE INDEX organization_invitation_page ON organization.invitations(tenant_id,organization_id,invitation_id);
CREATE INDEX organization_invitation_pending ON organization.invitations(tenant_id,organization_id,expires_at) WHERE state='pending';
ALTER TABLE organization.command_effects ADD COLUMN invitation_id identity.directory_id;
ALTER TABLE organization.command_effects ADD CHECK(
 (operation IN('identity.organization.invitation-send','identity.organization.invitation.accept') AND invitation_id IS NOT NULL)
 OR (operation NOT IN('identity.organization.invitation-send','identity.organization.invitation.accept') AND invitation_id IS NULL)
);`
