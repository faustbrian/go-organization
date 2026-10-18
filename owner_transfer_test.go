package organization_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

func transferFixture(t *testing.T) (*organization.Service, organization.Authentication, *policyClock, *policyOwner, *recordingPolicy) {
	t.Helper()
	base, a, at, owner, policy := policyFixture(t)
	c, err := base.PrepareUpdate(t.Context(), updateRequest(t, a))
	if err != nil {
		t.Fatal(err)
	}
	x, err := c.Input()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := x.Session.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	reader := &policyReader{observation: session.SessionObservation{Session: x.Session.Session, Current: spec.Authority, Active: true, ReadStartedAt: at.now, ValidUntil: at.now.Add(20 * time.Second)}}
	sessions, err := session.NewSessionService(reader, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "organization-test", Clock: at, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := organization.NewService(sessions, owner, policy, organization.Config{Clock: at, MaximumDuration: time.Second, PolicyID: "organization", PolicyVersion: 1, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, OwnerTransferAudience: "organization-action", ValidateCanonicalID: func(context.Context, organization.ID) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	owner.reads, policy.calls = 0, 0
	return s, a, at, owner, policy
}

func transferRequest(t *testing.T, a organization.Authentication) organization.OwnerTransferRequest {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	proof := auth.ReauthenticationProof{Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "actor", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "organization-action", IssuedAt: at, ExpiresAt: at.Add(5 * time.Minute)}, SessionID: "session-a", SessionVersion: 1, Action: string(organization.OwnerTransfer)}
	return organization.OwnerTransferRequest{Authentication: a, CommandID: id, OrganizationID: "org", TargetUserID: "target", OrganizationVersion: 7, SourceVersion: 1, TargetVersion: 2, CorrelationID: "owner-transfer", Proof: proof}
}

func TestOwnerTransferPreparation(t *testing.T) {
	s, a, _, owner, policy := transferFixture(t)
	owner.view.Target.Role = organization.RoleMember
	r := transferRequest(t, a)
	c, err := s.PrepareOwnerTransfer(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	x, err := c.Input()
	if err != nil || x.Operation != organization.OwnerTransfer || x.Actor != owner.view.Actor || x.Target != owner.view.Target || x.Role != organization.RoleMember || x.Binding.UserID != "target" || x.Binding.ActorID != "actor" || x.Organization.Version != 7 || x.OwnerTransferProof != r.Proof || owner.writes != 0 {
		t.Fatal("transfer lost exact source/target or wrote during preparation", err)
	}
	if string(policy.last.Request.Action) != string(organization.OwnerTransfer) || policy.last.Request.Resource.ID != "org" {
		t.Fatal("wrong transfer authorization")
	}
	got, err := s.Execute(t.Context(), c, outcomeOwner(func(c organization.Command) (organization.StoreResult, error) {
		got, err := owner.Execute(t.Context(), c)
		got.Receipt.AuditEventID = "transfer-audit"
		return got, err
	}))
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.AfterVersion != 8 {
		t.Fatal("transfer handoff", err)
	}
}

func TestOwnerTransferDisabledWithoutExplicitAudience(t *testing.T) {
	s, a, _, owner, _ := policyFixture(t)
	_, err := s.PrepareOwnerTransfer(t.Context(), transferRequest(t, a))
	if !errors.Is(err, organization.ErrForbidden) || owner.reads != 0 {
		t.Fatal("disabled transfer reached organization storage", err)
	}
}

func TestOwnerTransferPolicyCannotRenewProofExpiry(t *testing.T) {
	s, a, at, owner, policy := transferFixture(t)
	owner.view.Target.Role = organization.RoleMember
	r := transferRequest(t, a)
	r.Proof.Proof.ExpiresAt = at.now.Add(time.Second)
	policy.beforeReturn = func() { at.now = r.Proof.Proof.ExpiresAt }
	if c, err := s.PrepareOwnerTransfer(t.Context(), r); !errors.Is(err, organization.ErrForbidden) || c != (organization.Command{}) || owner.writes != 0 {
		t.Fatal("preparation renewed expired proof", err)
	}
	// A fresh observer keeps this execution case independent of preparation's
	// clock advance; session clock rollback is correctly rejected on its own.
	s, a, at, owner, policy = transferFixture(t)
	owner.view.Target.Role = organization.RoleMember
	r = transferRequest(t, a)
	r.Proof.Proof.ExpiresAt = at.now.Add(time.Second)
	c, err := s.PrepareOwnerTransfer(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	policy.beforeReturn = func() { at.now = r.Proof.Proof.ExpiresAt }
	_, err = s.Execute(t.Context(), c, outcomeOwner(func(c organization.Command) (organization.StoreResult, error) { return owner.Execute(t.Context(), c) }))
	if !errors.Is(err, organization.ErrForbidden) || owner.writes != 0 {
		t.Fatal("execution renewed expired proof", err)
	}
}

func TestOwnerTransferRejectsInvalidAndForeignAuthority(t *testing.T) {
	for _, variant := range []string{"admin", "member", "removed-source", "removed-target", "owner-target", "self", "foreign-org", "foreign-tenant", "inactive-target", "stale-org", "stale-source", "stale-target", "zero-source", "overflow-target", "no-proof", "wrong-action", "wrong-session", "wrong-subject", "wrong-audience", "expired-proof", "old-proof"} {
		t.Run(variant, func(t *testing.T) {
			s, a, _, owner, _ := transferFixture(t)
			owner.view.Target.Role = organization.RoleMember
			r := transferRequest(t, a)
			want := organization.ErrForbidden
			switch variant {
			case "no-proof":
				r.Proof = auth.ReauthenticationProof{}
			case "wrong-action":
				r.Proof.Action = "identity.password.change"
			case "wrong-session":
				r.Proof.SessionID = "foreign"
			case "wrong-subject":
				r.Proof.Proof.Subject = "foreign"
			case "wrong-audience":
				r.Proof.Proof.Audience = "foreign"
			case "expired-proof":
				r.Proof.Proof.ExpiresAt = r.Proof.Proof.IssuedAt.Add(time.Second)
			case "old-proof":
				r.Proof.Proof.IssuedAt = r.Proof.Proof.IssuedAt.Add(-16 * time.Minute)
			case "admin":
				owner.view.Actor.Role = organization.RoleAdministrator
			case "member":
				owner.view.Actor.Role = organization.RoleMember
			case "removed-source":
				owner.view.Actor.Active = false
			case "removed-target":
				owner.view.Target.Active = false
			case "owner-target":
				owner.view.Target.Role = organization.RoleOwner
			case "self":
				r.TargetUserID = "actor"
			case "foreign-org":
				owner.view.Target.OrganizationID = "foreign"
			case "foreign-tenant":
				owner.view.Target.TenantID = "foreign"
			case "inactive-target":
				owner.view.TargetUser.Status = identity.StatusSuspended
			case "stale-org":
				r.OrganizationVersion--
				want = organization.ErrConflict
			case "stale-source":
				r.SourceVersion++
				want = organization.ErrConflict
			case "stale-target":
				r.TargetVersion--
				want = organization.ErrConflict
			case "zero-source":
				r.SourceVersion = 0
				want = organization.ErrInvalidInput
			case "overflow-target":
				r.TargetVersion = ^uint64(0)
				want = organization.ErrInvalidInput
			}
			c, err := s.PrepareOwnerTransfer(t.Context(), r)
			if !errors.Is(err, want) || c != (organization.Command{}) || owner.writes != 0 {
				t.Fatal("unsafe transfer admitted", err)
			}
		})
	}
}
