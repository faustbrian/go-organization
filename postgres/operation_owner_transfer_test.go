package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestOwnerTransferOperationRequiresNativeCustody(t *testing.T) {
	for _, service := range []*OperationService{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			got, err := service.OwnerTransfer(ctx, organization.OwnerTransferOperationRequest{}, "127.0.0.1")
			if !errors.Is(err, organization.ErrInvalidInput) || got != (organization.StoreResult{}) {
				t.Fatal("missing transfer custody manufactured authority")
			}
		}
	}
}

func TestOwnerTransferOperationIntentRetainsEveryOriginalField(t *testing.T) {
	at := time.Date(2026, 10, 26, 12, 0, 0, 1, time.UTC)
	r := organization.OwnerTransferOperationRequest{OrganizationID: "org", TargetUserID: "member", OrganizationVersion: 2, SourceVersion: 1, TargetVersion: 1, CorrelationID: "original", Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "owner", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "organization-action", IssuedAt: at, ExpiresAt: at.Add(5 * time.Minute)}, SessionID: "session", SessionVersion: 1, Action: string(organization.OwnerTransfer)}}
	const audience = "organization-action"
	original, err := identity.NewRequestIntent(ownerTransferOperationFields(r, audience))
	if err != nil {
		t.Fatal(err)
	}
	fields, ok := original.Fields()
	if !ok {
		t.Fatal("missing original transfer intent")
	}
	for name, change := range map[string]func(*organization.OwnerTransferOperationRequest, *string){
		"organization":         func(r *organization.OwnerTransferOperationRequest, _ *string) { r.OrganizationID = "other" },
		"target":               func(r *organization.OwnerTransferOperationRequest, _ *string) { r.TargetUserID = "other" },
		"organization-version": func(r *organization.OwnerTransferOperationRequest, _ *string) { r.OrganizationVersion++ },
		"source-version":       func(r *organization.OwnerTransferOperationRequest, _ *string) { r.SourceVersion++ },
		"target-version":       func(r *organization.OwnerTransferOperationRequest, _ *string) { r.TargetVersion++ },
		"proof-id":             func(r *organization.OwnerTransferOperationRequest, _ *string) { r.Proof.Proof.ID += "a" },
		"proof-tenant":         func(r *organization.OwnerTransferOperationRequest, _ *string) { r.Proof.Proof.Tenant = "other" },
		"proof-subject":        func(r *organization.OwnerTransferOperationRequest, _ *string) { r.Proof.Proof.Subject = "other" },
		"proof-method":         func(r *organization.OwnerTransferOperationRequest, _ *string) { r.Proof.Proof.Method = "other" },
		"proof-assurance": func(r *organization.OwnerTransferOperationRequest, _ *string) {
			r.Proof.Proof.Assurance = auth.AssuranceMultiFactor
		},
		"proof-purpose":  func(r *organization.OwnerTransferOperationRequest, _ *string) { r.Proof.Proof.Purpose = "other" },
		"proof-audience": func(r *organization.OwnerTransferOperationRequest, _ *string) { r.Proof.Proof.Audience = "other" },
		"proof-issued": func(r *organization.OwnerTransferOperationRequest, _ *string) {
			r.Proof.Proof.IssuedAt = r.Proof.Proof.IssuedAt.Add(-time.Nanosecond)
		},
		"proof-expiry": func(r *organization.OwnerTransferOperationRequest, _ *string) {
			r.Proof.Proof.ExpiresAt = r.Proof.Proof.ExpiresAt.Add(time.Nanosecond)
		},
		"proof-session":         func(r *organization.OwnerTransferOperationRequest, _ *string) { r.Proof.SessionID = "other" },
		"proof-session-version": func(r *organization.OwnerTransferOperationRequest, _ *string) { r.Proof.SessionVersion++ },
		"proof-action":          func(r *organization.OwnerTransferOperationRequest, _ *string) { r.Proof.Action = "other" },
		"configured-audience":   func(_ *organization.OwnerTransferOperationRequest, a *string) { *a = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed, selected := r, audience
			change(&changed, &selected)
			intent, err := identity.NewRequestIntent(ownerTransferOperationFields(changed, selected))
			if err != nil {
				t.Fatal(err)
			}
			got, _ := intent.Fields()
			if reflect.DeepEqual(fields, got) {
				t.Fatal("changed transfer intent was discarded")
			}
		})
	}
	r.CorrelationID = "new-diagnostic"
	r.Proof.Proof.IssuedAt = r.Proof.Proof.IssuedAt.In(time.FixedZone("offset", 3600))
	r.Proof.Proof.ExpiresAt = r.Proof.Proof.ExpiresAt.In(time.FixedZone("offset", 3600))
	intent, err := identity.NewRequestIntent(ownerTransferOperationFields(r, audience))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := intent.Fields()
	if !reflect.DeepEqual(fields, got) {
		t.Fatal("retry correlation/time location changed semantic intent")
	}
}
