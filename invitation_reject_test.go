package organization_test

import (
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestInvitationRejectBindsVerifiedRecipientWithoutProofOrMembership(t *testing.T) {
	base, auth, at, owner, _ := policyFixture(t)
	record := organization.Invitation{ID: "invitation-a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "actor", RecipientIdentifierID: "recipient-email", RecipientIdentifierVersion: 3, CreatedBy: "owner", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Now().Add(time.Hour)}
	r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, RecipientUser: identity.User{ID: "actor", TenantID: "tenant-a", Status: identity.StatusActive, Version: 1}, RecipientIdentifier: identity.Identifier{ID: "recipient-email", UserID: "actor", Kind: identity.IdentifierEmail, CanonicalValue: "recipient@example.invalid", DisplayValue: "recipient@example.invalid", Verified: true, Primary: true, Version: 3}, Record: organization.InvitationDelivery{Invitation: record}}}
	s, err := organization.NewInvitationService(base, r, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.PrepareReject(t.Context(), organization.InvitationRejectRequest{Authentication: auth, CommandID: id, ID: record.ID, OrganizationID: record.OrganizationID, OrganizationVersion: 7, InvitationVersion: 1, CorrelationID: "reject"})
	if err != nil {
		t.Fatal(err)
	}
	x, err := c.Input()
	if err != nil || x.Operation != organization.InvitationReject || x.Binding.UserID != "actor" || x.Binding.ActorID != "actor" || x.Target.Active || x.Invitation.Record != record {
		t.Fatal("rejection lost exact recipient custody", err)
	}
	result, err := base.Execute(t.Context(), c, &invitationWork{})
	if err != nil || result.Receipt.Feature.BeforeVersion != 1 || result.Receipt.Feature.AfterVersion != 2 {
		t.Fatal("rejection lost terminal invitation version", err)
	}
}

func TestInvitationRejectDeniesWrongRecipientAndWithdrawnAuthority(t *testing.T) {
	for _, variant := range []string{"recipient", "tenant", "org", "inactive-org", "stale-org", "stale-invitation", "unverified", "identifier-version", "suspended", "accepted", "cancelled", "rejected", "expired", "late-session", "execution-expiry"} {
		t.Run(variant, func(t *testing.T) {
			base, auth, at, owner, policy := policyFixture(t)
			record := organization.Invitation{ID: "invitation-a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "actor", RecipientIdentifierID: "recipient-email", RecipientIdentifierVersion: 3, CreatedBy: "owner", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Now().Add(time.Hour)}
			r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, RecipientUser: identity.User{ID: "actor", TenantID: "tenant-a", Status: identity.StatusActive, Version: 1}, RecipientIdentifier: identity.Identifier{ID: "recipient-email", UserID: "actor", Kind: identity.IdentifierEmail, CanonicalValue: "recipient@example.invalid", DisplayValue: "recipient@example.invalid", Verified: true, Primary: true, Version: 3}, Record: organization.InvitationDelivery{Invitation: record}}}
			switch variant {
			case "recipient":
				r.snapshot.Record.Invitation.RecipientUserID = "other"
			case "tenant":
				r.snapshot.Record.Invitation.TenantID = "other"
			case "org":
				r.snapshot.Record.Invitation.OrganizationID = "other"
			case "inactive-org":
				r.snapshot.Organization.Active = false
			case "stale-org":
				r.snapshot.Organization.Version++
			case "stale-invitation":
				record.Version++
			case "unverified":
				r.snapshot.RecipientIdentifier.Verified = false
			case "identifier-version":
				r.snapshot.RecipientIdentifier.Version++
			case "suspended":
				r.snapshot.RecipientUser.Status = identity.StatusSuspended
			case "accepted":
				r.snapshot.Record.Invitation.Status, r.snapshot.Record.Invitation.Version = organization.InvitationAccepted, 2
			case "cancelled":
				r.snapshot.Record.Invitation.Status, r.snapshot.Record.Invitation.Version = organization.InvitationCancelled, 2
			case "rejected":
				r.snapshot.Record.Invitation.Status, r.snapshot.Record.Invitation.Version = organization.InvitationRejected, 2
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
			c, err := s.PrepareReject(t.Context(), organization.InvitationRejectRequest{Authentication: auth, CommandID: id, ID: record.ID, OrganizationID: record.OrganizationID, OrganizationVersion: 7, InvitationVersion: record.Version, CorrelationID: "reject-denied"})
			if variant != "execution-expiry" {
				if err == nil {
					t.Fatal("unauthorized, stale or terminal rejection admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			at.now = record.ExpiresAt
			if _, err = base.Execute(t.Context(), c, &invitationWork{}); !errors.Is(err, organization.ErrForbidden) {
				t.Fatal("prepared rejection renewed exclusive deadline", err)
			}
		})
	}
}
