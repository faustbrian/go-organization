package organization_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

type domainObserver struct {
	observation organization.DomainObservation
	calls       int
}

func (o *domainObserver) ObserveDomain(context.Context, organization.DomainClaim) (organization.DomainObservation, error) {
	o.calls++
	return o.observation, nil
}

func TestDomainEvidenceFreezesOriginalObservation(t *testing.T) {
	s, a, c, owner, _ := policyFixtureConfig(t, organization.TeamConfig{}, organization.DomainConfig{Version: 1, MaximumClaims: 20, EvidenceMaximumAge: time.Hour})
	claim := organization.DomainClaim{ID: "claim", OrganizationID: "org", TenantID: "tenant-a", Domain: "example.com", Version: 1, State: organization.DomainRequested}
	owner.view.DomainClaim = claim
	observer := &domainObserver{observation: organization.DomainObservation{Claim: claim, Method: organization.DomainDNS, ObservedAt: c.now, ExpiresAt: c.now.Add(time.Minute), Verified: true}}
	id, _ := identity.NewCommandID()
	request := organization.DomainEvidenceRequest{Claim: organization.DomainClaimRequest{Authentication: a, CommandID: id, OrganizationID: "org", ClaimID: "claim", OrganizationVersion: 7, ClaimVersion: 1, Domain: "example.com", CorrelationID: "evidence"}}
	command, err := s.PrepareDomainEvidence(t.Context(), request, observer)
	if err != nil {
		t.Fatal(err)
	}
	x, err := command.Command().Input()
	if err != nil || x.DomainProof.ObservedAt != c.now || x.DomainProof.ExpiresAt != observer.observation.ExpiresAt || x.DomainProof.ProofVersion != 1 || observer.calls != 1 {
		t.Fatal("observation not frozen", err)
	}
	observer.observation.ExpiresAt = c.now.Add(time.Hour)
	again, _ := command.Command().Input()
	if again.DomainProof != x.DomainProof {
		t.Fatal("caller mutated original proof")
	}
}

func TestDomainEvidenceRejectsUnverifiedOrMismatchedObservation(t *testing.T) {
	for _, variant := range []string{"unverified", "scope", "expired", "future", "method", "excess-lifetime"} {
		t.Run(variant, func(t *testing.T) {
			s, a, c, owner, _ := policyFixtureConfig(t, organization.TeamConfig{}, organization.DomainConfig{Version: 1, MaximumClaims: 20, EvidenceMaximumAge: time.Hour})
			claim := organization.DomainClaim{ID: "claim", OrganizationID: "org", TenantID: "tenant-a", Domain: "example.com", Version: 1, State: organization.DomainRequested}
			owner.view.DomainClaim = claim
			observation := organization.DomainObservation{Claim: claim, Method: organization.DomainDNS, ObservedAt: c.now, ExpiresAt: c.now.Add(time.Minute), Verified: true}
			switch variant {
			case "unverified":
				observation.Verified = false
			case "scope":
				observation.Claim.TenantID = "other"
			case "expired":
				observation.ExpiresAt = c.now
			case "future":
				observation.ObservedAt = c.now.Add(time.Second)
			case "method":
				observation.Method = "caller-asserted"
			case "excess-lifetime":
				observation.ExpiresAt = c.now.Add(2 * time.Hour)
			}
			id, _ := identity.NewCommandID()
			_, err := s.PrepareDomainEvidence(t.Context(), organization.DomainEvidenceRequest{Claim: organization.DomainClaimRequest{Authentication: a, CommandID: id, OrganizationID: "org", ClaimID: "claim", OrganizationVersion: 7, ClaimVersion: 1, Domain: "example.com", CorrelationID: "evidence"}}, &domainObserver{observation: observation})
			if !errors.Is(err, organization.ErrForbidden) {
				t.Fatal("invalid observation admitted", err)
			}
		})
	}
}

func TestDomainEvidenceExpiryDeniesCoreWorkAfterPolicy(t *testing.T) {
	s, a, at, owner, policy := policyFixtureConfig(t, organization.TeamConfig{}, organization.DomainConfig{Version: 1, MaximumClaims: 20, EvidenceMaximumAge: time.Hour})
	claim := organization.DomainClaim{ID: "claim", OrganizationID: "org", TenantID: "tenant-a", Domain: "example.com", Version: 1, State: organization.DomainRequested}
	owner.view.DomainClaim = claim
	observer := &domainObserver{observation: organization.DomainObservation{Claim: claim, Method: organization.DomainDNS, ObservedAt: at.now, ExpiresAt: at.now.Add(time.Second), Verified: true}}
	id, _ := identity.NewCommandID()
	c, err := s.PrepareDomainEvidence(t.Context(), organization.DomainEvidenceRequest{Claim: organization.DomainClaimRequest{Authentication: a, CommandID: id, OrganizationID: "org", ClaimID: "claim", OrganizationVersion: 7, ClaimVersion: 1, Domain: "example.com", CorrelationID: "evidence"}}, observer)
	if err != nil {
		t.Fatal(err)
	}
	policy.beforeReturn = func() { at.now = observer.observation.ExpiresAt }
	if _, err = s.Execute(t.Context(), c.Command(), owner); !errors.Is(err, organization.ErrForbidden) || owner.writes != 0 {
		t.Fatal("policy wait renewed original proof expiry", err)
	}
}
