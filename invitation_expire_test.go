package organization_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestInvitationExpireFreezesAuthorizedVersionAndRegisteredReason(t *testing.T) {
	base, auth, at, owner, _ := policyFixture(t)
	record := organization.Invitation{ID: "invitation-a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "target", RecipientIdentifierID: "recipient-email", RecipientIdentifierVersion: 1, CreatedBy: "actor", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Now().Add(time.Hour)}
	r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, Actor: owner.view.Actor, Record: organization.InvitationDelivery{Invitation: record}}}
	reasons := []identity.PolicyReason{"security-withdrawal"}
	s, err := organization.NewInvitationService(base, r, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100, ExpirationReasons: reasons})
	if err != nil {
		t.Fatal(err)
	}
	reasons[0] = "caller-mutated"
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.PrepareExpire(t.Context(), organization.InvitationExpireRequest{Authentication: auth, CommandID: id, ID: record.ID, OrganizationID: record.OrganizationID, OrganizationVersion: 7, InvitationVersion: 1, Reason: "security-withdrawal", CorrelationID: "expire"})
	if err != nil {
		t.Fatal(err)
	}
	x, err := c.Input()
	if err != nil || x.Operation != organization.InvitationExpire || x.Invitation.ExpirationReason != "security-withdrawal" || x.Binding.UserID != "actor" || x.Binding.ActorID != "actor" || x.Invitation.Record != record {
		t.Fatal("expiry lost admin/record/reason custody", err)
	}
	result, err := base.Execute(t.Context(), c, &invitationWork{})
	if err != nil || result.Receipt.Feature.BeforeVersion != 1 || result.Receipt.Feature.AfterVersion != 2 {
		t.Fatal("expiry lost terminal invitation transition", err)
	}
}

func TestInvitationExpireDeniesUnregisteredStaleOrTerminalAuthority(t *testing.T) {
	for _, variant := range []string{"admin", "member", "removed", "foreign", "stale-org", "stale-invitation", "accepted", "cancelled", "rejected", "terminal-expired", "natural-expired", "unregistered", "reason-empty", "reason-long", "late-session"} {
		t.Run(variant, func(t *testing.T) {
			base, auth, at, owner, policy := policyFixture(t)
			record := organization.Invitation{ID: "invitation-a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "target", RecipientIdentifierID: "email", RecipientIdentifierVersion: 1, CreatedBy: "actor", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Now().Add(time.Hour)}
			r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, Actor: owner.view.Actor, Record: organization.InvitationDelivery{Invitation: record}}}
			reason := identity.PolicyReason("security-withdrawal")
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
			case "rejected":
				r.snapshot.Record.Invitation.Status, r.snapshot.Record.Invitation.Version = organization.InvitationRejected, 2
			case "terminal-expired":
				r.snapshot.Record.Invitation.Status, r.snapshot.Record.Invitation.Version = organization.InvitationExpired, 2
			case "natural-expired":
				r.snapshot.Record.Invitation.Status, r.snapshot.Record.Invitation.ExpiresAt = organization.InvitationExpired, at.Now()
			case "unregistered":
				reason = "other"
			case "reason-empty":
				reason = ""
			case "reason-long":
				reason = identity.PolicyReason(strings.Repeat("r", 65))
			case "late-session":
				policy.beforeReturn = func() { at.now = at.now.Add(time.Minute) }
			}
			s, err := organization.NewInvitationService(base, r, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100, ExpirationReasons: []identity.PolicyReason{"security-withdrawal"}})
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			c, err := s.PrepareExpire(t.Context(), organization.InvitationExpireRequest{Authentication: auth, CommandID: id, ID: record.ID, OrganizationID: record.OrganizationID, OrganizationVersion: 7, InvitationVersion: record.Version, Reason: reason, CorrelationID: "expire-case"})
			if variant != "admin" && variant != "natural-expired" {
				if err == nil {
					t.Fatal("denied expiry admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out, err := base.Execute(t.Context(), c, &invitationWork{}); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("authorized pending expiry failed", err)
			}
			if _, err := base.Execute(t.Context(), c, &invitationWork{malformed: true}); !errors.Is(err, organization.ErrUnavailable) {
				t.Fatal("expiry accepted wrong aggregate receipt", err)
			}
		})
	}
}

func TestInvitationExpireReasonsAreBounded(t *testing.T) {
	base, _, at, _, _ := policyFixture(t)
	for _, reasons := range [][]identity.PolicyReason{{""}, {"duplicate", "duplicate"}, {identity.PolicyReason(strings.Repeat("r", 65))}, make([]identity.PolicyReason, 33)} {
		if _, err := organization.NewInvitationService(base, &invitationPolicyRepository{}, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100, ExpirationReasons: reasons}); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("invalid reason registry admitted", err)
		}
	}
}
