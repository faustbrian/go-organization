package organization_test

import (
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestInvitationCancelFreezesCurrentAdministratorAndPendingVersion(t *testing.T) {
	for _, variant := range []string{"owner", "admin", "member", "removed", "foreign", "stale-org", "stale-invitation", "accepted", "cancelled", "expired", "late-session"} {
		t.Run(variant, func(t *testing.T) {
			base, auth, at, owner, policy := policyFixture(t)
			record := organization.Invitation{ID: "invitation-a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "target", RecipientIdentifierID: "recipient-email", RecipientIdentifierVersion: 1, CreatedBy: "actor", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Now().Add(time.Hour)}
			r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, Actor: owner.view.Actor, Record: organization.InvitationDelivery{Invitation: record}}}
			switch variant {
			case "admin":
				r.snapshot.Actor.Role = organization.RoleAdministrator
			case "member":
				r.snapshot.Actor.Role = organization.RoleMember
			case "removed":
				r.snapshot.Actor.Active = false
			case "foreign":
				r.snapshot.Record.Invitation.TenantID = "foreign"
			case "stale-org":
				r.snapshot.Organization.Version++
			case "stale-invitation":
				record.Version++
			case "accepted":
				r.snapshot.Record.Invitation.Status, r.snapshot.Record.Invitation.Version = organization.InvitationAccepted, 2
			case "cancelled":
				r.snapshot.Record.Invitation.Status, r.snapshot.Record.Invitation.Version = organization.InvitationCancelled, 2
			case "expired":
				r.snapshot.Record.Invitation.ExpiresAt = at.Now()
			case "late-session":
				policy.beforeReturn = func() { at.now = at.now.Add(time.Minute) }
			}
			s, err := organization.NewInvitationService(base, r, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100})
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			request := organization.InvitationCancelRequest{Authentication: auth, CommandID: id, ID: "invitation-a", OrganizationID: "org", OrganizationVersion: 7, InvitationVersion: record.Version, CorrelationID: "cancel"}
			c, err := s.PrepareCancel(t.Context(), request)
			if variant != "owner" && variant != "admin" {
				if err == nil {
					t.Fatal("unauthorized, stale or terminal cancellation admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			x, err := c.Input()
			if err != nil {
				t.Fatal(err)
			}
			if x.Operation != organization.InvitationCancel || string(x.Binding.UserID) != string(x.Binding.ActorID) || x.Binding.RecordID != "invitation-a" || x.Invitation.Record != record || x.Invitation.RecipientIdentifier.ID != "" {
				t.Fatal("cancel lost exact self/record custody or required recipient secrets")
			}
			out, err := base.Execute(t.Context(), c, &invitationWork{})
			if err != nil || out.Receipt.Feature.BeforeVersion != 1 || out.Receipt.Feature.AfterVersion != 2 {
				t.Fatal("cancel did not use invitation aggregate", err)
			}
			_, err = base.Execute(t.Context(), c, &invitationWork{malformed: true})
			if !errors.Is(err, organization.ErrUnavailable) {
				t.Fatal("cancel accepted organization-version receipt", err)
			}
			at.now = record.ExpiresAt
			if _, err := base.Execute(t.Context(), c, &invitationWork{}); !errors.Is(err, organization.ErrForbidden) {
				t.Fatal("cancel renewed original exclusive deadline", err)
			}
		})
	}
}
