//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// Only the supported application policy callback is controlled. Real session,
// member, command-key and journal owners remain unchanged and currently valid.
type selectionHistoryPolicy struct {
	base     authorization.Service
	resource authorization.ResourceType
	blocked  atomic.Bool
	denials  atomic.Int32
}

func (p *selectionHistoryPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if p.blocked.Load() && c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Action == authorization.Action(organization.ActiveSet) && c.Request.Resource.Type == p.resource {
		p.denials.Add(1)
		return authorization.Decision{Outcome: authorization.Deny, Revision: c.PolicyRevision}, nil
	}
	return p.base.Decide(ctx, c)
}

func (f *activeOrganizationFixture) exerciseSelectionHistoryPolicy(t *testing.T, request organization.ActiveOrganizationOperationRequest, original organization.StoreResult) {
	t.Helper()
	for _, resource := range []authorization.ResourceType{"session", "identity.user"} {
		base, err := fixtureAuthorization()
		if err != nil {
			t.Fatal(err)
		}
		policy := &selectionHistoryPolicy{base: base, resource: resource}
		policy.blocked.Store(true)
		participant, configuration := selectionOrganizationComposition(t, f.pool, f.sessions, f.profile, f.lookup, f.keys, f.material, organization.DynamicRoleConfig{}, nil, nil, true)
		query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
		coordinator, err := kernel.NewCoordinator(f.pool, configuration.Registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: f.keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query})
		if err != nil {
			t.Fatal(err)
		}
		configuration.Authorization, configuration.Coordinator = policy, coordinator
		source, err := organizationpg.NewService(participant, configuration)
		if err != nil {
			t.Fatal(err)
		}
		service := f.operationsFromSource(t, f.pool, source, policy)
		before := f.record(t, request.Authentication)
		for _, invoke := range []struct {
			name string
			run  func() (organization.StoreResult, error)
		}{
			{"matching-key", func() (organization.StoreResult, error) {
				return service.SetActiveOrganization(f.ctx, request, "127.0.0.1")
			}},
			{"explicit-recovery", func() (organization.StoreResult, error) {
				return service.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: request.Authentication, Binding: original.Receipt.Binding})
			}},
		} {
			result, err := invoke.run()
			if !errors.Is(err, organization.ErrForbidden) || result.Receipt != (identity.CommandResult{}) || result.OrganizationID != "" {
				t.Fatalf("%s denied %s policy disclosed original binding/history: forbidden=%t receipt_zero=%t", invoke.name, resource, errors.Is(err, organization.ErrForbidden), result.Receipt == (identity.CommandResult{}))
			}
		}
		if policy.denials.Load() < 2 {
			t.Fatal("distinct recovery policy was not exercised", resource)
		}
		policy.blocked.Store(false)
		recovered, err := service.SetActiveOrganization(f.ctx, request, "127.0.0.1")
		if err != nil || !reflect.DeepEqual(recovered, original) {
			t.Fatal("policy control changed original committed history or underlying current authority", resource, err)
		}
		if after := f.record(t, request.Authentication); !reflect.DeepEqual(before, after) {
			t.Fatal("denied/authorized historical lookup mutated session selection or freshness", resource)
		}
	}
}
