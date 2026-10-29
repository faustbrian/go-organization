package organization_test

import (
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
)

func TestCredentialAuthorityObservationSeparatesOwnerAndOptionalActor(t *testing.T) {
	at := time.Date(2026, 10, 29, 4, 0, 0, 0, time.UTC)
	q := organization.CredentialAuthorityQuery{TenantID: "tenant", OrganizationID: "org"}
	o := organization.CredentialAuthorityObservation{TenantID: q.TenantID, OrganizationID: q.OrganizationID, Version: 7, CredentialVersion: 1, ReadStartedAt: at, VerifiedAt: at.Add(time.Millisecond), ValidUntil: at.Add(20 * time.Second)}
	if err := o.Validate(q, at.Add(time.Second)); err != nil {
		t.Fatal("owner-only authority requires no human", err)
	}
	q.ActorID = "actual-member"
	if err := o.Validate(q, at.Add(time.Second)); err == nil {
		t.Fatal("owner authority manufactured membership")
	}
	o.Actor = organization.Member{TenantID: q.TenantID, OrganizationID: q.OrganizationID, UserID: q.ActorID, Version: 2, AuthorizationVersion: 3, Role: organization.RoleMember, Active: true}
	if err := o.Validate(q, at.Add(time.Second)); err != nil {
		t.Fatal("actual independently versioned member rejected", err)
	}
	q.ActorID = ""
	if err := o.Validate(q, at.Add(time.Second)); err == nil {
		t.Fatal("optional actor silently discarded")
	}
}

func TestCredentialAuthorityObservationRejectsChangedBindingsAndRenewedFreshness(t *testing.T) {
	at := time.Date(2026, 10, 29, 4, 0, 0, 0, time.UTC)
	q := organization.CredentialAuthorityQuery{TenantID: "tenant", OrganizationID: "org", ActorID: "member"}
	original := organization.CredentialAuthorityObservation{TenantID: q.TenantID, OrganizationID: q.OrganizationID, Version: 7, CredentialVersion: 1, Actor: organization.Member{TenantID: q.TenantID, OrganizationID: q.OrganizationID, UserID: q.ActorID, Version: 2, AuthorizationVersion: 3, Role: organization.RoleMember, Active: true}, ReadStartedAt: at, VerifiedAt: at.Add(time.Millisecond), ValidUntil: at.Add(20 * time.Second)}
	for name, change := range map[string]func(*organization.CredentialAuthorityObservation){
		"tenant":                      func(o *organization.CredentialAuthorityObservation) { o.TenantID = "other" },
		"organization":                func(o *organization.CredentialAuthorityObservation) { o.OrganizationID = "other" },
		"policy epoch":                func(o *organization.CredentialAuthorityObservation) { o.Version = 0 },
		"credential epoch":            func(o *organization.CredentialAuthorityObservation) { o.CredentialVersion = 0 },
		"removed member":              func(o *organization.CredentialAuthorityObservation) { o.Actor.Active = false },
		"foreign member":              func(o *organization.CredentialAuthorityObservation) { o.Actor.UserID = "other" },
		"foreign member organization": func(o *organization.CredentialAuthorityObservation) { o.Actor.OrganizationID = "other" },
		"foreign member tenant":       func(o *organization.CredentialAuthorityObservation) { o.Actor.TenantID = "other" },
		"unknown role":                func(o *organization.CredentialAuthorityObservation) { o.Actor.Role = "unknown" },
		"zero member epoch":           func(o *organization.CredentialAuthorityObservation) { o.Actor.Version = 0 },
		"zero policy epoch":           func(o *organization.CredentialAuthorityObservation) { o.Actor.AuthorizationVersion = 0 },
		"future read":                 func(o *organization.CredentialAuthorityObservation) { o.ReadStartedAt = at.Add(2 * time.Second) },
		"future verification":         func(o *organization.CredentialAuthorityObservation) { o.VerifiedAt = at.Add(2 * time.Second) },
		"verification before read":    func(o *organization.CredentialAuthorityObservation) { o.VerifiedAt = at.Add(-time.Second) },
		"renewed expiry":              func(o *organization.CredentialAuthorityObservation) { o.ValidUntil = at.Add(21 * time.Second) },
		"expired":                     func(o *organization.CredentialAuthorityObservation) { o.ValidUntil = at.Add(time.Second) },
		"verification after validity": func(o *organization.CredentialAuthorityObservation) { o.ValidUntil = at.Add(time.Microsecond) },
	} {
		t.Run(name, func(t *testing.T) {
			o := original
			change(&o)
			if err := o.Validate(q, at.Add(time.Second)); err == nil {
				t.Fatal("invalid projection admitted")
			}
		})
	}
	for _, q := range []organization.CredentialAuthorityQuery{{}, {TenantID: "tenant", OrganizationID: "bad id"}, {TenantID: "tenant", OrganizationID: "org", ActorID: "bad id"}} {
		if err := q.Validate(); err == nil {
			t.Fatal("malformed authority query admitted")
		}
	}
	if err := (organization.CredentialAuthorityObservation{}).Validate(q, at); err == nil {
		t.Fatal("zero projection admitted")
	}
}
