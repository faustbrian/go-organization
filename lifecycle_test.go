package organization_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func commandIDForLifecycle(t *testing.T) identity.CommandID {
	t.Helper()
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	return id
}

func lifecycleRequest(t *testing.T, a organization.Authentication, op organization.Operation) organization.LifecycleRequest {
	r := transferRequest(t, a)
	r.Proof.Action = string(op)
	return organization.LifecycleRequest{Authentication: a, CommandID: r.CommandID, OrganizationID: r.OrganizationID, OrganizationVersion: r.OrganizationVersion, Reason: "maintenance", CorrelationID: "lifecycle", Proof: r.Proof}
}

func TestLifecycleOwnerProofStateAndVersionPreparation(t *testing.T) {
	s, a, _, owner, _ := transferFixture(t, organization.LifecycleConfig{Version: 1, ProofAudience: "organization-action"})
	owner.view.LifecycleState = organization.LifecycleActive
	r := lifecycleRequest(t, a, organization.Archive)
	c, e := s.PrepareArchive(t.Context(), r)
	if e != nil {
		t.Fatal(e)
	}
	x, e := c.Input()
	if e != nil || x.LifecycleProof != r.Proof || x.LifecycleReason != r.Reason || x.LifecycleState != organization.LifecycleActive || x.Binding.SchemaID != "organization-lifecycle" || x.Binding.UserID != "actor" || owner.writes != 0 {
		t.Fatal("archive lost frozen owner intent", e)
	}
	r.OrganizationVersion--
	if _, e = s.PrepareArchive(t.Context(), r); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("stale lifecycle epoch accepted", e)
	}
	owner.view.Organization.Active = false
	owner.view.LifecycleState = organization.LifecycleArchived
	view, e := s.GetLifecycle(t.Context(), organization.ReadRequest{Authentication: a, OrganizationID: "org", CorrelationID: "lifecycle"})
	if e != nil || view.LifecycleState != organization.LifecycleArchived || view.Organization.Active {
		t.Fatal("archived owner cannot discover restore version", e)
	}
	r = lifecycleRequest(t, a, organization.Restore)
	if _, e = s.PrepareRestore(t.Context(), r); e != nil {
		t.Fatal("current archived owner cannot prepare restore", e)
	}
	owner.view.Actor.Role = organization.RoleAdministrator
	if _, e = s.GetLifecycle(t.Context(), organization.ReadRequest{Authentication: a, OrganizationID: "org", CorrelationID: "lifecycle"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("administrator discovered owner lifecycle", e)
	}
	if _, e = s.PrepareRestore(t.Context(), r); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("administrator restored organization", e)
	}
}

func TestLifecyclePolicyCannotRenewActionProof(t *testing.T) {
	s, a, at, owner, policy := transferFixture(t, organization.LifecycleConfig{Version: 1, ProofAudience: "organization-action"})
	owner.view.LifecycleState = organization.LifecycleActive
	r := lifecycleRequest(t, a, organization.Archive)
	r.Proof.Action = string(organization.Restore)
	if _, e := s.PrepareArchive(t.Context(), r); !errors.Is(e, organization.ErrForbidden) || owner.reads != 0 {
		t.Fatal("different-action proof reached owner", e)
	}
	r.Proof.Action = string(organization.Archive)
	r.Proof.Proof.ExpiresAt = at.now.Add(time.Second)
	policy.beforeReturn = func() { at.now = r.Proof.Proof.ExpiresAt }
	if _, e := s.PrepareArchive(t.Context(), r); !errors.Is(e, organization.ErrForbidden) || owner.writes != 0 {
		t.Fatal("policy renewed lifecycle proof", e)
	}
}

func FuzzLifecycleReasonBoundary(f *testing.F) {
	for _, reason := range []string{"maintenance", "", "with space", "\x00", strings.Repeat("x", 65)} {
		f.Add(reason)
	}
	f.Fuzz(func(t *testing.T, reason string) {
		if len(reason) > 256 {
			return
		}
		s, a, _, owner, _ := transferFixture(t, organization.LifecycleConfig{Version: 1, ProofAudience: "organization-action"})
		owner.view.LifecycleState = organization.LifecycleActive
		r := lifecycleRequest(t, a, organization.Archive)
		r.Reason = reason
		_, e := s.PrepareArchive(t.Context(), r)
		valid := len(reason) > 0 && len(reason) <= 64
		for _, b := range []byte(reason) {
			if b < 33 || b > 126 {
				valid = false
			}
		}
		if valid && e != nil {
			t.Fatal("valid reason denied", e)
		}
		if !valid && (!errors.Is(e, organization.ErrInvalidInput) || owner.reads != 0) {
			t.Fatal("unbounded lifecycle reason reached owner", e)
		}
	})
}

func TestLifecycleDisabledDoesNotReadOrPrepareAuthority(t *testing.T) {
	s, a, _, owner, _ := policyFixture(t)
	r := organization.LifecycleRequest{Authentication: a, CommandID: commandIDForLifecycle(t), OrganizationID: "org", OrganizationVersion: 7, Reason: "maintenance", CorrelationID: "lifecycle"}
	if _, e := s.PrepareArchive(t.Context(), r); !errors.Is(e, organization.ErrForbidden) || owner.reads != 0 {
		t.Fatal("disabled archive reached authority", e)
	}
	if _, e := s.PrepareRestore(t.Context(), r); !errors.Is(e, organization.ErrForbidden) || owner.reads != 0 {
		t.Fatal("disabled restore reached authority", e)
	}
	if _, e := s.GetLifecycle(t.Context(), organization.ReadRequest{Authentication: a, OrganizationID: "org", CorrelationID: "lifecycle"}); !errors.Is(e, organization.ErrForbidden) || owner.reads != 0 {
		t.Fatal("disabled lifecycle discovery reached authority", e)
	}
}
