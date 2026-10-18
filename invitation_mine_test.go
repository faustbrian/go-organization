package organization_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

type invitationMineReader struct {
	invitationPolicyRepository
	snapshot organization.InvitationListMineSnapshot
	read     func() error
}

func (r *invitationMineReader) ReadInvitationsMine(_ context.Context, q organization.InvitationListMineQuery) (organization.InvitationListMineSnapshot, error) {
	if r.read != nil {
		if err := r.read(); err != nil {
			return organization.InvitationListMineSnapshot{}, err
		}
	}
	s := r.snapshot
	s.Identifiers = append([]organization.InvitationRecipientIdentifier(nil), s.Identifiers...)
	s.Invitations = nil
	for _, i := range r.snapshot.Invitations {
		if i.ID > q.After && len(s.Invitations) <= int(q.Limit) {
			s.Invitations = append(s.Invitations, i)
		}
	}
	return s, nil
}

func TestInvitationListMineIsSelfScopedStableAndLifecycleComplete(t *testing.T) {
	base, auth, at, _, _ := policyFixture(t)
	r := &invitationMineReader{snapshot: organization.InvitationListMineSnapshot{Recipient: identity.User{ID: "actor", TenantID: "tenant-a", Status: identity.StatusActive, Version: 1}, IdentifierAuthorityVersion: 1, Identifiers: []organization.InvitationRecipientIdentifier{{ID: "recipient-email", Version: 3}}}}
	for n, status := range []organization.InvitationStatus{organization.InvitationPending, organization.InvitationAccepted, organization.InvitationCancelled, organization.InvitationPending} {
		version := uint64(1)
		if status == organization.InvitationAccepted || status == organization.InvitationCancelled {
			version = 2
		}
		i := organization.Invitation{ID: organization.ID(string(rune('a' + n))), OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "actor", RecipientIdentifierID: "recipient-email", RecipientIdentifierVersion: 3, CreatedBy: "owner", Role: organization.RoleMember, Status: status, Version: version, ExpiresAt: at.Now().Add(time.Hour)}
		if n == 3 {
			i.ExpiresAt = at.Now()
		}
		r.snapshot.Invitations = append(r.snapshot.Invitations, i)
	}
	s, err := organization.NewInvitationService(base, r, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100})
	if err != nil {
		t.Fatal(err)
	}
	request := organization.InvitationListMineRequest{Authentication: auth, Limit: 2, CorrelationID: "mine"}
	first, err := s.ListMine(t.Context(), request)
	if err != nil || len(first.Invitations) != 2 || first.NextCursor == "" || first.Invitations[0].Status != organization.InvitationPending || first.Invitations[1].Status != organization.InvitationAccepted {
		t.Fatal("self without organization membership lost lifecycle page", err)
	}
	request.Cursor = first.NextCursor
	second, err := s.ListMine(t.Context(), request)
	if err != nil || len(second.Invitations) != 2 || second.NextCursor != "" || second.Invitations[0].Status != organization.InvitationCancelled || second.Invitations[1].Status != organization.InvitationExpired {
		t.Fatal("stable second lifecycle page missing", err)
	}
	first.Invitations[0].ID = "changed"
	if r.snapshot.Invitations[0].ID != "a" {
		t.Fatal("result aliases native projection")
	}
	request.Limit = 201
	if _, err = s.ListMine(t.Context(), request); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("overlarge page admitted", err)
	}
}

func TestInvitationListMineRejectsUnscopedOrWithdrawnProjection(t *testing.T) {
	for _, variant := range []string{"foreign-recipient", "foreign-tenant", "unverified-identifier", "unknown-state", "duplicate", "cancel-during-policy", "recipient-during-policy", "identifier-during-policy", "epoch-during-policy", "session-expiry", "context-cancelled", "no-optional-reader", "policy-deny", "policy-unknown", "policy-revision", "second-read-error", "second-policy-error"} {
		t.Run(variant, func(t *testing.T) {
			base, auth, at, _, policy := policyFixture(t)
			r := &invitationMineReader{snapshot: organization.InvitationListMineSnapshot{Recipient: identity.User{ID: "actor", TenantID: "tenant-a", Status: identity.StatusActive, Version: 1}, IdentifierAuthorityVersion: 1, Identifiers: []organization.InvitationRecipientIdentifier{{ID: "email", Version: 1}}, Invitations: []organization.Invitation{{ID: "a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "actor", RecipientIdentifierID: "email", RecipientIdentifierVersion: 1, CreatedBy: "owner", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Now().Add(time.Hour)}}}}
			failure := errors.New("private dependency diagnostic")
			reads, limit := 0, uint32(2)
			switch variant {
			case "second-read-error", "second-policy-error":
				second := r.snapshot.Invitations[0]
				second.ID = "b"
				r.snapshot.Invitations = append(r.snapshot.Invitations, second)
				limit = 1
				r.read = func() error {
					reads++
					if variant == "second-read-error" && reads == 2 {
						return failure
					}
					return nil
				}
				if variant == "second-policy-error" {
					policy.beforeReturn = func() {
						if policy.calls == 2 {
							policy.err = failure
						}
					}
				}
			case "policy-deny":
				policy.outcome = authorization.Deny
			case "policy-unknown":
				policy.outcome = 0
			case "policy-revision":
				policy.revision = 2
			case "foreign-recipient":
				r.snapshot.Invitations[0].RecipientUserID = "other"
			case "foreign-tenant":
				r.snapshot.Invitations[0].TenantID = "other"
			case "unverified-identifier":
				r.snapshot.Identifiers = nil
			case "unknown-state":
				r.snapshot.Invitations[0].Status = 99
			case "duplicate":
				r.snapshot.Invitations = append(r.snapshot.Invitations, r.snapshot.Invitations[0])
			case "cancel-during-policy":
				policy.beforeReturn = func() {
					r.snapshot.Invitations[0].Status = organization.InvitationCancelled
					r.snapshot.Invitations[0].Version = 2
				}
			case "recipient-during-policy":
				policy.beforeReturn = func() { r.snapshot.Recipient.Version++ }
			case "identifier-during-policy":
				policy.beforeReturn = func() { r.snapshot.Identifiers = nil }
			case "epoch-during-policy":
				policy.beforeReturn = func() { r.snapshot.IdentifierAuthorityVersion++ }
			case "session-expiry":
				policy.beforeReturn = func() { at.now = at.now.Add(time.Minute) }
			}
			var reader organization.InvitationRepository = r
			if variant == "no-optional-reader" {
				reader = &invitationPolicyRepository{}
			}
			s, e := organization.NewInvitationService(base, reader, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if variant == "context-cancelled" {
				cancel()
			}
			result, e := s.ListMine(ctx, organization.InvitationListMineRequest{Authentication: auth, Limit: limit, CorrelationID: "mine-denied"})
			if e == nil || len(result.Invitations) != 0 || result.NextCursor != "" {
				t.Fatal("untrusted/stale partial invitation page escaped", e)
			}
			if variant == "second-read-error" || variant == "second-policy-error" {
				wantReads := 1
				if variant == "second-read-error" {
					wantReads = 2
				}
				if e != organization.ErrUnavailable || errors.Is(e, failure) || reads != wantReads || policy.calls != 2 {
					t.Fatal("late operational failure was not reached and redacted", e, reads, policy.calls)
				}
			}
		})
	}
}
