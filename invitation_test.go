package organization_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	organization "github.com/faustbrian/go-organization"
)

// Controlled core-policy projections are not native recipient/session proof.
// The genuine PostgreSQL consumer must exercise actual signup and shared owners.
type invitationPolicyRepository struct {
	snapshot organization.InvitationSnapshot
	page     organization.InvitationPage
}

type invitationWork struct{ malformed bool }

func (w *invitationWork) Execute(_ context.Context, c organization.Command) (organization.StoreResult, error) {
	x, err := c.Input()
	if err != nil {
		return organization.StoreResult{}, err
	}
	before := x.Invitation.Record.Version
	if w.malformed {
		before = x.Organization.Version
	}
	return organization.StoreResult{OrganizationID: x.Organization.ID, MemberID: x.TargetUser.ID, InvitationID: x.Invitation.Record.ID, Receipt: identity.CommandResult{Binding: x.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "invitation-audit", Feature: &identity.FeatureReceipt{Operation: x.Operation.Descriptor(), BeforeVersion: before, AfterVersion: before + 1}}}, nil
}
func (*invitationWork) Recover(context.Context, identity.CommandID) (organization.StoreResult, error) {
	return organization.StoreResult{}, organization.ErrForbidden
}

func TestInvitationExecuteValidatesInvitationAggregateNotOrganization(t *testing.T) {
	base, auth, at, owner, _ := policyFixture(t)
	r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, Actor: owner.view.Actor, RecipientUser: owner.view.TargetUser, RecipientIdentifier: identity.Identifier{ID: "recipient-email", UserID: "target", Kind: identity.IdentifierEmail, CanonicalValue: "recipient@example.invalid", DisplayValue: "recipient@example.invalid", Verified: true, Primary: true, Version: 1}}}
	s, err := organization.NewInvitationService(base, r, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.PrepareSend(t.Context(), organization.InvitationSendRequest{Authentication: auth, CommandID: id, ID: "invitation-a", OrganizationID: "org", OrganizationVersion: 7, RecipientUserID: "target", RecipientIdentifierID: "recipient-email", CorrelationID: "send"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := base.Execute(t.Context(), c, &invitationWork{})
	if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.InvitationID != "invitation-a" || out.Receipt.Feature.BeforeVersion != 0 || out.Receipt.Feature.AfterVersion != 1 {
		t.Fatal("invitation0→1 receipt rejected in favor of unrelated organization7→8", err)
	}
	out, err = base.Execute(t.Context(), c, &invitationWork{malformed: true})
	if !errors.Is(err, organization.ErrUnavailable) || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.InvitationID != "invitation-a" {
		t.Fatal("unattributable invitation receipt accepted", err)
	}
}

func (r *invitationPolicyRepository) ReadInvitation(context.Context, organization.InvitationQuery) (organization.InvitationSnapshot, error) {
	return r.snapshot, nil
}
func (r *invitationPolicyRepository) ListInvitations(context.Context, organization.InvitationQuery) (organization.InvitationPage, error) {
	return r.page, nil
}

func TestInvitationMetadataIsOwnerScopedBoundedAndBearerFree(t *testing.T) {
	for _, variant := range []string{"valid", "removed-owner", "ordinary-member", "cross-org", "impossible-version", "session-expires-during-policy", "unordered-page", "oversized-page"} {
		t.Run(variant, func(t *testing.T) {
			base, auth, at, owner, policy := policyFixture(t)
			i := organization.InvitationDelivery{Invitation: organization.Invitation{ID: "invitation-a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "target", RecipientIdentifierID: "recipient-email", RecipientIdentifierVersion: 1, CreatedBy: "actor", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Now().Add(time.Hour)}, EffectID: delivery.IntentID("organization-invitation-effect"), State: delivery.StateQueued}
			r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, Actor: owner.view.Actor, Record: i}, page: organization.InvitationPage{Organization: owner.view.Organization, Actor: owner.view.Actor, Invitations: []organization.InvitationDelivery{i}}}
			switch variant {
			case "removed-owner":
				r.snapshot.Actor.Active = false
				r.page.Actor.Active = false
			case "ordinary-member":
				r.snapshot.Actor.Role = organization.RoleMember
				r.page.Actor.Role = organization.RoleMember
			case "cross-org":
				r.snapshot.Record.Invitation.OrganizationID = "other"
				r.page.Invitations[0].Invitation.OrganizationID = "other"
			case "impossible-version":
				r.snapshot.Record.Invitation.Version = 2
				r.page.Invitations[0].Invitation.Version = 2
			case "session-expires-during-policy":
				policy.beforeReturn = func() { at.now = at.now.Add(time.Minute) }
			case "unordered-page":
				r.page.Invitations = append(r.page.Invitations, i)
			case "oversized-page":
				r.page.Invitations = append(r.page.Invitations, i, i)
			}
			s, err := organization.NewInvitationService(base, r, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100})
			if err != nil {
				t.Fatal(err)
			}
			request := organization.InvitationReadRequest{Authentication: auth, OrganizationID: "org", ID: "invitation-a", CorrelationID: "metadata"}
			if variant != "unordered-page" && variant != "oversized-page" {
				out, err := s.Get(t.Context(), request)
				if variant != "valid" {
					if err == nil {
						t.Fatal("invalid metadata admitted")
					}
					return
				}
				if err != nil || out != i {
					t.Fatal("safe current metadata missing", err)
				}
				wire, err := json.Marshal(out)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(wire), "@") || strings.Contains(string(wire), "Proof") || strings.Contains(string(wire), "CanonicalValue") {
					t.Fatal("metadata leaked recipient address or capability")
				}
			}
			request.ID = ""
			request.Limit = 2
			page, err := s.List(t.Context(), request)
			if variant != "valid" {
				if err == nil {
					t.Fatal("malformed/unscoped page admitted")
				}
				return
			}
			if err != nil || len(page.Invitations) != 1 || page.Invitations[0] != i {
				t.Fatal("safe invitation page missing", err)
			}
			page.Invitations[0].Invitation.ID = "changed"
			if r.page.Invitations[0].Invitation.ID != "invitation-a" {
				t.Fatal("public page aliases owned repository data")
			}
		})
	}
}

func invitationCrypto(t *testing.T, at *policyClock) capability.Service {
	t.Helper()
	signer, e := capability.NewHMACSHA256Signer("invitation", bytes.Repeat([]byte{0x71}, 32))
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{0x71}, 32))
	if e != nil {
		t.Fatal(e)
	}
	keys, e := capability.NewKeySet([]capability.Key{{Issuer: "organization-test", ID: "invitation", Verifier: verifier}})
	if e != nil {
		t.Fatal(e)
	}
	limits := capability.DefaultLimits()
	limits.MaxLifetime = 30 * 24 * time.Hour
	crypto, e := capability.NewService(capability.ServiceConfig{Issuer: "organization-test", Signer: signer, Resolver: keys, Clock: at.Now, Limits: limits})
	if e != nil {
		t.Fatal(e)
	}
	return crypto
}

func TestInvitationSendFreezesOwnerRecipientAndExpiry(t *testing.T) {
	base, auth, at, owner, _ := policyFixture(t)
	crypto := invitationCrypto(t, at)
	r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, Actor: owner.view.Actor, RecipientUser: owner.view.TargetUser, RecipientIdentifier: identity.Identifier{ID: "recipient-email", UserID: "target", Kind: identity.IdentifierEmail, CanonicalValue: "recipient@example.invalid", DisplayValue: "recipient@example.invalid", Verified: true, Primary: true, Version: 1}}}
	s, e := organization.NewInvitationService(base, r, crypto, organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100})
	if e != nil {
		t.Fatal(e)
	}
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.PrepareSend(t.Context(), organization.InvitationSendRequest{Authentication: auth, CommandID: id, ID: "invitation-a", OrganizationID: "org", OrganizationVersion: 7, RecipientUserID: "target", RecipientIdentifierID: "recipient-email", CorrelationID: "invite"})
	if e != nil {
		t.Fatal(e)
	}
	x, e := p.Input()
	if e != nil {
		t.Fatal(e)
	}
	if x.Binding.ActorID != "actor" || x.Binding.UserID != "target" || x.Binding.RecordID != "invitation-a" || x.Operation != organization.InvitationSend || x.Invitation.Record.OrganizationID != "org" || x.Invitation.Record.Role != organization.RoleMember || !x.Invitation.Record.ExpiresAt.Equal(at.Now().Add(48*time.Hour)) || x.Invitation.MaximumPending != 100 {
		t.Fatal("invitation substituted its original owner, recipient, organization or expiry")
	}
	r.snapshot.Actor.Active = false
	if _, e = s.PrepareSend(t.Context(), organization.InvitationSendRequest{Authentication: auth, CommandID: id, ID: "invitation-b", OrganizationID: "org", OrganizationVersion: 7, RecipientUserID: "target", RecipientIdentifierID: "recipient-email", CorrelationID: "invite"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("removed owner admitted invitation", e)
	}
}

func TestInvitationAcceptRequiresExactVerifiedRecipientGrant(t *testing.T) {
	for _, variant := range []string{"valid", "expires-after-preparation", "other-recipient", "other-organization", "other-identifier", "other-identifier-version", "other-role", "missing-caveat", "extra-caveat", "reusable", "expired", "already-member", "already-accepted", "unverified", "stale-policy", "session-expires-during-policy"} {
		t.Run(variant, func(t *testing.T) {
			base, auth, at, owner, policy := policyFixture(t)
			crypto := invitationCrypto(t, at)
			record := organization.Invitation{ID: "invitation-a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "actor", RecipientIdentifierID: "recipient-email", RecipientIdentifierVersion: 3, CreatedBy: "owner", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Now().Add(48 * time.Hour)}
			if variant == "expires-after-preparation" {
				record.ExpiresAt = at.Now().Add(2 * time.Second)
			}
			r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, RecipientUser: identity.User{ID: "actor", TenantID: "tenant-a", Status: identity.StatusActive, Version: 1}, RecipientIdentifier: identity.Identifier{ID: "recipient-email", UserID: "actor", Kind: identity.IdentifierEmail, CanonicalValue: "recipient@example.invalid", DisplayValue: "recipient@example.invalid", Verified: true, Primary: true, Version: 3}, Record: organization.InvitationDelivery{Invitation: record}}}
			payload := capability.Payload{Version: 1, Issuer: "organization-test", Audiences: []string{"organization-invitation"}, Subject: "actor", Resource: "invitation-a", Operation: string(organization.InvitationAccept), ID: "invitation-capability", Tenant: "tenant-a", MaxUses: 1, ExpiresAt: record.ExpiresAt, Caveats: map[string]string{"organization.id": "org", "organization.invitation-version": "1", "organization.role": "member", "organization.recipient-identifier": "recipient-email", "organization.recipient-identifier-version": "3"}}
			switch variant {
			case "other-recipient":
				payload.Subject = "other"
			case "other-organization":
				payload.Caveats["organization.id"] = "other"
			case "other-identifier":
				payload.Caveats["organization.recipient-identifier"] = "other"
			case "other-identifier-version":
				payload.Caveats["organization.recipient-identifier-version"] = "4"
			case "other-role":
				payload.Caveats["organization.role"] = "owner"
			case "missing-caveat":
				delete(payload.Caveats, "organization.id")
			case "extra-caveat":
				payload.Caveats["other"] = "unselected"
			case "reusable":
				payload.MaxUses = 0
			case "already-member":
				r.snapshot.Target = owner.view.Actor
			case "already-accepted":
				r.snapshot.Record.Invitation.Status = organization.InvitationAccepted
				r.snapshot.Record.Invitation.Version = 2
			case "unverified":
				r.snapshot.RecipientIdentifier.Verified = false
			case "stale-policy":
				policy.revision = 2
			case "session-expires-during-policy":
				policy.beforeReturn = func() { at.now = at.now.Add(time.Minute) }
			}
			proof, _, err := crypto.Issue(t.Context(), payload)
			if err != nil {
				t.Fatal(err)
			}
			if variant == "expired" {
				at.now = record.ExpiresAt
			}
			s, err := organization.NewInvitationService(base, r, crypto, organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100})
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			command, err := s.PrepareAccept(t.Context(), organization.InvitationAcceptRequest{Authentication: auth, CommandID: id, ID: record.ID, OrganizationID: record.OrganizationID, InvitationVersion: 1, OrganizationVersion: 7, Proof: proof, CorrelationID: "accept"})
			want := organization.ErrForbidden
			if variant == "already-member" || variant == "already-accepted" {
				want = organization.ErrConflict
			}
			if variant != "valid" && variant != "expires-after-preparation" {
				if !errors.Is(err, want) {
					t.Fatalf("invalid acceptance admitted or misclassified: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			x, err := command.Input()
			if err != nil {
				t.Fatal(err)
			}
			if x.Binding.ActorID != "actor" || x.Binding.UserID != "actor" || x.Binding.RecordID != "invitation-a" || x.Invitation.Record.Version != 1 || x.Invitation.Record.Role != organization.RoleMember || x.Target.Active {
				t.Fatal("acceptance changed recipient, invitation or member authority")
			}
			if variant == "expires-after-preparation" {
				at.now = record.ExpiresAt
				if _, err := base.Execute(t.Context(), command, &invitationWork{}); !errors.Is(err, organization.ErrForbidden) {
					t.Fatal("original exclusive invitation expiry renewed by prepared execution", err)
				}
			}
		})
	}
}
