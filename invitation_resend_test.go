package organization_test

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	organization "github.com/faustbrian/go-organization"
)

func resendFixture(t *testing.T) (*organization.InvitationService, *organization.Service, organization.InvitationResendRequest, *invitationPolicyRepository, *policyClock, *recordingPolicy) {
	t.Helper()
	base, auth, at, owner, policy := policyFixture(t)
	// This remaining grant lifetime is shorter than the original session's
	// 20-second observation, so the exact-deadline oracle cannot pass merely
	// because the session also expired. Resend never chooses a fresh lifetime.
	i := organization.Invitation{ID: "invitation-a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "target", RecipientIdentifierID: "recipient-email", RecipientIdentifierVersion: 3, CreatedBy: "actor", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Now().Add(10 * time.Second)}
	r := &invitationPolicyRepository{snapshot: organization.InvitationSnapshot{Organization: owner.view.Organization, Actor: owner.view.Actor, RecipientUser: owner.view.TargetUser, RecipientIdentifier: identity.Identifier{ID: "recipient-email", UserID: "target", Kind: identity.IdentifierEmail, CanonicalValue: "recipient@example.invalid", DisplayValue: "recipient@example.invalid", Verified: true, Primary: true, Version: 3}, Record: organization.InvitationDelivery{Invitation: i, EffectID: delivery.IntentID("organization-invitation-effect"), State: delivery.StateQueued}, PendingCount: 100}}
	s, err := organization.NewInvitationService(base, r, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return s, base, organization.InvitationResendRequest{Authentication: auth, CommandID: id, ID: i.ID, OrganizationID: i.OrganizationID, OrganizationVersion: 7, InvitationVersion: 1, CorrelationID: "resend"}, r, at, policy
}

func TestInvitationResendFreezesRecipientRoleAndOriginalDeadline(t *testing.T) {
	for _, role := range []organization.Role{organization.RoleOwner, organization.RoleAdministrator} {
		s, base, request, repository, at, policy := resendFixture(t)
		repository.snapshot.Actor.Role = role
		c, err := s.PrepareResend(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		x, err := c.Input()
		if err != nil || x.Operation != organization.InvitationResend || x.Binding.RecordID != string(request.ID) || x.Binding.CommandID != request.CommandID || x.Binding.UserID != "target" || x.Binding.ActorID != "actor" || x.Invitation.Record != repository.snapshot.Record.Invitation || x.Invitation.RecipientIdentifier != repository.snapshot.RecipientIdentifier || x.Invitation.MaximumPending != 100 || x.Role != organization.RoleMember {
			t.Fatal("resend lost immutable predecessor/recipient/role/deadline intent", err)
		}
		if policy.last.Request.Action != authorization.Action(organization.InvitationResend) || policy.last.Request.Resource.ID != "org" {
			t.Fatal("resend aliased send or selected a foreign action/resource")
		}
		got, err := base.Execute(t.Context(), c, &invitationWork{})
		if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.BeforeVersion != 1 || got.Receipt.Feature.AfterVersion != 2 {
			t.Fatal("resend used organization epoch instead of invitation transition", err)
		}
		if _, err := base.Execute(t.Context(), c, &invitationWork{malformed: true}); !errors.Is(err, organization.ErrUnavailable) {
			t.Fatal("resend accepted unrelated organization receipt", err)
		}
		at.now = x.Invitation.Record.ExpiresAt
		if _, err := base.Execute(t.Context(), c, &invitationWork{}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("resend renewed the original invitation deadline", err)
		}
	}
}

func TestInvitationResendDeniesForeignStaleTerminalOrWithdrawnAuthority(t *testing.T) {
	for _, variant := range []string{"member", "removed-actor", "foreign-org", "foreign-tenant", "foreign-recipient", "wrong-identifier", "identifier-version", "unverified", "inactive-recipient", "active-member", "role-escalation", "stale-org", "stale-invitation", "zero-version", "overflow-version", "no-terminal-version", "state-no-terminal-version", "accepted", "cancelled", "rejected", "terminal-expired", "natural-expired", "exclusive-deadline", "denied-policy", "late-session"} {
		t.Run(variant, func(t *testing.T) {
			s, _, request, repository, at, policy := resendFixture(t)
			want := organization.ErrForbidden
			switch variant {
			case "member":
				repository.snapshot.Actor.Role = organization.RoleMember
			case "removed-actor":
				repository.snapshot.Actor.Active = false
			case "foreign-org":
				repository.snapshot.Record.Invitation.OrganizationID = "other"
			case "foreign-tenant":
				repository.snapshot.Record.Invitation.TenantID = "other"
			case "foreign-recipient":
				repository.snapshot.RecipientUser.ID = "other"
			case "wrong-identifier":
				repository.snapshot.RecipientIdentifier.ID = "other"
			case "identifier-version":
				repository.snapshot.RecipientIdentifier.Version++
			case "unverified":
				repository.snapshot.RecipientIdentifier.Verified = false
			case "inactive-recipient":
				repository.snapshot.RecipientUser.Status = identity.StatusSuspended
			case "active-member":
				repository.snapshot.Target.Active, want = true, organization.ErrConflict
			case "role-escalation":
				repository.snapshot.Record.Invitation.Role = organization.RoleOwner
			case "stale-org":
				request.OrganizationVersion, want = 6, organization.ErrConflict
			case "stale-invitation":
				request.InvitationVersion, want = 2, organization.ErrConflict
			case "zero-version":
				request.InvitationVersion, want = 0, organization.ErrInvalidInput
			case "overflow-version":
				request.InvitationVersion, want = ^uint64(0), organization.ErrInvalidInput
			case "no-terminal-version":
				request.InvitationVersion, want = ^uint64(0)-1, organization.ErrInvalidInput
			case "state-no-terminal-version":
				request.InvitationVersion, want = ^uint64(0)-1, organization.ErrInvalidInput
				repository.snapshot.Record.Invitation.Version = request.InvitationVersion
				repository.snapshot.Record.Invitation.IssuedVersion = request.InvitationVersion
			case "accepted":
				repository.snapshot.Record.Invitation.Status, repository.snapshot.Record.Invitation.Version = organization.InvitationAccepted, 2
			case "cancelled":
				repository.snapshot.Record.Invitation.Status, repository.snapshot.Record.Invitation.Version = organization.InvitationCancelled, 2
			case "rejected":
				repository.snapshot.Record.Invitation.Status, repository.snapshot.Record.Invitation.Version = organization.InvitationRejected, 2
			case "terminal-expired":
				repository.snapshot.Record.Invitation.Status, repository.snapshot.Record.Invitation.Version = organization.InvitationExpired, 2
			case "natural-expired":
				repository.snapshot.Record.Invitation.Status = organization.InvitationExpired
			case "exclusive-deadline":
				repository.snapshot.Record.Invitation.ExpiresAt = at.Now()
			case "denied-policy":
				policy.outcome = authorization.Deny
			case "late-session":
				policy.beforeReturn = func() { at.now = at.now.Add(time.Minute) }
			}
			c, err := s.PrepareResend(t.Context(), request)
			if !errors.Is(err, want) || c != (organization.Command{}) {
				t.Fatal("unsafe resend prepared", err, want)
			}
		})
	}
}

func TestInvitationResendRetainsNaturalAndExplicitExpiryDistinction(t *testing.T) {
	_, base, request, repository, at, _ := resendFixture(t)
	s, err := organization.NewInvitationService(base, repository, invitationCrypto(t, at), organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100, ExpirationReasons: []identity.PolicyReason{"security-withdrawal"}})
	if err != nil {
		t.Fatal(err)
	}
	repository.snapshot.Record.Invitation.Status, repository.snapshot.Record.Invitation.Version, repository.snapshot.Record.Invitation.IssuedVersion = organization.InvitationExpired, 3, 3
	repository.snapshot.Record.Invitation.ExpiresAt = at.Now()
	expire := organization.InvitationExpireRequest{Authentication: request.Authentication, CommandID: request.CommandID, ID: request.ID, OrganizationID: request.OrganizationID, OrganizationVersion: request.OrganizationVersion, InvitationVersion: 3, Reason: "security-withdrawal", CorrelationID: "resend-expiry"}
	c, err := s.PrepareExpire(t.Context(), expire)
	if err != nil {
		t.Fatal("natural expiry after resends could not be terminalized", err)
	}
	got, err := base.Execute(t.Context(), c, &invitationWork{})
	if err != nil || got.Receipt.Feature.BeforeVersion != 3 || got.Receipt.Feature.AfterVersion != 4 {
		t.Fatal("resend expiry changed the wrong version", err)
	}
	repository.snapshot.Record.Invitation.Version = 4
	expire.InvitationVersion = 4
	if _, err := s.PrepareExpire(t.Context(), expire); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("explicit terminal expiry after resends became pending again", err)
	}
	repository.snapshot.Record.Invitation.Version, repository.snapshot.Record.Invitation.IssuedVersion, expire.InvitationVersion = 2, 0, 2
	if _, err := s.PrepareExpire(t.Context(), expire); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("legacy terminal expiry lost its meaning", err)
	}
}

func TestInvitationResendRetainsPositiveIssuedVersionAndTerminalProjection(t *testing.T) {
	s, base, request, repository, at, _ := resendFixture(t)
	repository.snapshot.Record.Invitation.Version = 3
	repository.snapshot.Record.Invitation.IssuedVersion = 3
	request.InvitationVersion = 3
	c, err := s.PrepareResend(t.Context(), request)
	if err != nil {
		t.Fatal("subsequent resend treated later pending version as terminal", err)
	}
	got, err := base.Execute(t.Context(), c, &invitationWork{})
	if err != nil || got.Receipt.Feature.BeforeVersion != 3 || got.Receipt.Feature.AfterVersion != 4 {
		t.Fatal("subsequent resend lost exact positive version", err)
	}
	for _, state := range []organization.InvitationStatus{organization.InvitationAccepted, organization.InvitationCancelled, organization.InvitationRejected, organization.InvitationExpired} {
		repository.snapshot.Record.Invitation.Status, repository.snapshot.Record.Invitation.Version = state, 4
		metadata, err := s.Get(t.Context(), organization.InvitationReadRequest{Authentication: request.Authentication, OrganizationID: request.OrganizationID, ID: request.ID, CorrelationID: "resend-terminal"})
		if err != nil || metadata.Invitation.Version != 4 || metadata.Invitation.IssuedVersion != 3 || metadata.Invitation.Status != state {
			t.Fatal("later terminal version lost issued generation", err)
		}
		if _, err := s.PrepareResend(t.Context(), request); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("terminal resend admitted", err)
		}
	}
	// Natural expiry keeps the pending version; an explicit expiry is the next
	// record version after its last issued proof. Legacy zero still means one.
	repository.snapshot.Record.Invitation.Status, repository.snapshot.Record.Invitation.Version = organization.InvitationPending, 3
	repository.snapshot.Record.Invitation.ExpiresAt = at.Now()
	metadata, err := s.Get(t.Context(), organization.InvitationReadRequest{Authentication: request.Authentication, OrganizationID: request.OrganizationID, ID: request.ID, CorrelationID: "resend-natural"})
	if err != nil || metadata.Invitation.Status != organization.InvitationExpired || metadata.Invitation.Version != metadata.Invitation.IssuedVersion {
		t.Fatal("natural expiry lost pending proof generation", err)
	}
}
