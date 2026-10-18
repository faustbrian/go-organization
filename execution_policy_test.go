package organization_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// These are root policy/handoff tests. Native persistence and current authority
// are covered by the PostgreSQL consumer; the callback is a consumer-owned seam.
func TestExecutionRepeatsCurrentPolicyBeforeProtectedWork(t *testing.T) {
	for _, op := range []organization.Operation{organization.Create, organization.RemoveMember, organization.InvitationSend, organization.InvitationAccept} {
		for _, variant := range []string{"denied", "wrong-revision", "expires-during-policy", "canceled-during-policy", "allowed"} {
			t.Run(string(op)+"/"+variant, func(t *testing.T) {
				s, a, at, owner, policy := policyFixture(t)
				id, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				var command organization.Command
				switch op {
				case organization.Create:
					command, err = s.PrepareCreate(t.Context(), organization.CreateRequest{Authentication: a, CommandID: id, ID: "new-org", Slug: "new", Name: "New", CorrelationID: "execute-policy"})
				case organization.RemoveMember:
					r := memberRequest(t, a)
					r.CommandID, r.CorrelationID = id, "execute-policy"
					command, err = s.PrepareRemoveMember(t.Context(), r)
				case organization.InvitationSend, organization.InvitationAccept:
					crypto := invitationCrypto(t, at)
					record := organization.Invitation{ID: "invitation-a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "actor", RecipientIdentifierID: "recipient-email", RecipientIdentifierVersion: 3, CreatedBy: "owner", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Now().Add(48 * time.Hour)}
					r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, Actor: owner.view.Actor, RecipientUser: identity.User{ID: "actor", TenantID: "tenant-a", Status: identity.StatusActive, Version: 1}, RecipientIdentifier: identity.Identifier{ID: "recipient-email", UserID: "actor", Kind: identity.IdentifierEmail, CanonicalValue: "recipient@example.invalid", DisplayValue: "recipient@example.invalid", Verified: true, Primary: true, Version: 3}, Record: organization.InvitationDelivery{Invitation: record}}}
					inv, e := organization.NewInvitationService(s, r, crypto, organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100})
					if e != nil {
						t.Fatal(e)
					}
					if op == organization.InvitationSend {
						r.snapshot.Record = organization.InvitationDelivery{}
						command, err = inv.PrepareSend(t.Context(), organization.InvitationSendRequest{Authentication: a, CommandID: id, ID: record.ID, OrganizationID: "org", OrganizationVersion: 7, RecipientUserID: "actor", RecipientIdentifierID: "recipient-email", CorrelationID: "execute-policy"})
					} else {
						proof, _, e := crypto.Issue(t.Context(), capability.Payload{Version: 1, Issuer: "organization-test", Audiences: []string{"organization-invitation"}, Subject: "actor", Resource: "invitation-a", Operation: string(op), ID: "invitation-capability", Tenant: "tenant-a", MaxUses: 1, ExpiresAt: record.ExpiresAt, Caveats: map[string]string{"organization.id": "org", "organization.invitation-version": "1", "organization.role": "member", "organization.recipient-identifier": "recipient-email", "organization.recipient-identifier-version": "3"}})
						if e != nil {
							t.Fatal(e)
						}
						command, err = inv.PrepareAccept(t.Context(), organization.InvitationAcceptRequest{Authentication: a, CommandID: id, ID: record.ID, OrganizationID: "org", InvitationVersion: 1, OrganizationVersion: 7, Proof: proof, CorrelationID: "execute-policy"})
					}
				}
				if err != nil {
					t.Fatal("prepare allowed command", err)
				}
				original := policy.last
				calls := policy.calls
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				want := organization.ErrForbidden
				switch variant {
				case "denied":
					policy.outcome = authorization.Deny
				case "wrong-revision":
					policy.revision++
				case "expires-during-policy":
					policy.beforeReturn = func() { at.now = at.now.Add(20 * time.Second) }
				case "canceled-during-policy":
					policy.beforeReturn, want = cancel, context.Canceled
				case "allowed":
					want = organization.ErrUnavailable
				}
				writes := 0
				_, err = s.Execute(ctx, command, outcomeOwner(func(organization.Command) (organization.StoreResult, error) {
					writes++
					return organization.StoreResult{}, organization.ErrUnavailable
				}))
				if !errors.Is(err, want) {
					t.Fatalf("execution policy not enforced: %v", err)
				}
				if writes != 0 && variant != "allowed" || writes != 1 && variant == "allowed" {
					t.Fatal("protected work crossed denied or expired admission", writes)
				}
				if policy.calls != calls+1 || policy.last.PolicyRevision != original.PolicyRevision || policy.last.CorrelationID != original.CorrelationID || policy.last.Request.Action != original.Request.Action || !reflect.DeepEqual(policy.last.Request.Subject, original.Request.Subject) || policy.last.Request.Tenant != original.Request.Tenant || !reflect.DeepEqual(policy.last.Request.Resource, original.Request.Resource) {
					t.Fatal("execution omitted or substituted the original policy scope")
				}
			})
		}
	}
}
