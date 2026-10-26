package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestLifecycleOperationRejectsMissingNativeCustody(t *testing.T) {
	for _, service := range []*OperationService{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			for _, invoke := range []func(context.Context, organization.LifecycleOperationRequest, string) (organization.StoreResult, error){service.Archive, service.Restore} {
				got, err := invoke(ctx, organization.LifecycleOperationRequest{}, "127.0.0.1")
				if !errors.Is(err, organization.ErrInvalidInput) || got != (organization.StoreResult{}) {
					t.Fatal("missing lifecycle owner manufactured authority")
				}
			}
		}
	}
}

func TestLifecycleOperationIntentBindsCompleteOriginalProof(t *testing.T) {
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	r := organization.LifecycleOperationRequest{OrganizationID: "org", OrganizationVersion: 1, Reason: "maintenance", CorrelationID: "original", Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "owner", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "organization-action", IssuedAt: at, ExpiresAt: at.Add(5 * time.Minute)}, SessionID: "session", SessionVersion: 1, Action: string(organization.Archive)}}
	config := organization.LifecycleConfig{Version: 1, ProofAudience: "organization-action"}
	original, err := identity.NewRequestIntent(lifecycleOperationFields(r, config))
	if err != nil {
		t.Fatal(err)
	}
	fields, ok := original.Fields()
	if !ok {
		t.Fatal("missing original lifecycle intent")
	}
	for name, change := range map[string]func(*organization.LifecycleOperationRequest, *organization.LifecycleConfig){
		"organization": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.OrganizationID = "other"
		},
		"version": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.OrganizationVersion++
		},
		"reason": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) { r.Reason = "other" },
		"proof-id": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Proof.ID += "a"
		},
		"proof-tenant": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Proof.Tenant = "other"
		},
		"proof-subject": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Proof.Subject = "other"
		},
		"proof-method": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Proof.Method = "other"
		},
		"proof-assurance": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Proof.Assurance = auth.AssuranceMultiFactor
		},
		"proof-purpose": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Proof.Purpose = "other"
		},
		"proof-audience": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Proof.Audience = "other"
		},
		"proof-issued": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Proof.IssuedAt = r.Proof.Proof.IssuedAt.Add(-time.Second)
		},
		"proof-expiry": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Proof.ExpiresAt = r.Proof.Proof.ExpiresAt.Add(time.Second)
		},
		"proof-issued-nanosecond": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Proof.IssuedAt = r.Proof.Proof.IssuedAt.Add(-time.Nanosecond)
		},
		"proof-session": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.SessionID = "other"
		},
		"proof-session-version": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.SessionVersion++
		},
		"proof-action": func(r *organization.LifecycleOperationRequest, _ *organization.LifecycleConfig) {
			r.Proof.Action = string(organization.Restore)
		},
		"policy-version": func(_ *organization.LifecycleOperationRequest, c *organization.LifecycleConfig) { c.Version++ },
		"policy-audience": func(_ *organization.LifecycleOperationRequest, c *organization.LifecycleConfig) {
			c.ProofAudience = "other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed, policy := r, config
			change(&changed, &policy)
			intent, err := identity.NewRequestIntent(lifecycleOperationFields(changed, policy))
			if err != nil {
				t.Fatal(err)
			}
			got, _ := intent.Fields()
			if reflect.DeepEqual(fields, got) {
				t.Fatal("changed original lifecycle intent was discarded")
			}
		})
	}
	r.CorrelationID = "retry-keeps-original"
	r.Proof.Proof.IssuedAt = r.Proof.Proof.IssuedAt.In(time.FixedZone("offset", 3600))
	r.Proof.Proof.ExpiresAt = r.Proof.Proof.ExpiresAt.In(time.FixedZone("offset", 3600))
	intent, err := identity.NewRequestIntent(lifecycleOperationFields(r, config))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := intent.Fields()
	if !reflect.DeepEqual(fields, got) {
		t.Fatal("retry correlation/time location changed original semantic intent")
	}
}

func TestLifecycleOperationCodecRetainsOnlyOriginalBinding(t *testing.T) {
	for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
		p, b, original := operationCodecFixture(t)
		p.op, b.Scope.RouteID, b.Feature.Operation = op, string(op), op.Descriptor()
		original.OperationID, original.SchemaID = string(op), "organization-lifecycle"
		plain, err := json.Marshal(operationStoredBinding(original))
		if err != nil {
			t.Fatal(err)
		}
		wire := sealOperationFixture(t, p, b, plain)
		if got, err := p.restoreInput(t.Context(), b, wire); err != nil || got != original {
			t.Fatal("original lifecycle binding could not be authenticated", err)
		}
		b.Scope.RouteID = string(organization.OwnerTransfer)
		if got, err := p.restoreInput(t.Context(), b, wire); err == nil || got != (identity.CommandBinding{}) {
			t.Fatal("lifecycle ciphertext crossed operation scope")
		}
	}
}
