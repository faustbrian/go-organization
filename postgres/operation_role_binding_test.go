package postgres_test

import (
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

type directRoleBindingOperation interface {
	AssignDynamicRole(context.Context, organization.AssignDynamicRoleOperationRequest, string) (organization.StoreResult, error)
	RevokeDynamicRole(context.Context, organization.RevokeDynamicRoleOperationRequest, string) (organization.StoreResult, error)
}

func TestDirectRoleBindingOperationMigrationBounds(t *testing.T) {
	for _, version := range []migrations.Version{0, 1, migrations.Version(math.MaxInt64), migrations.Version(math.MaxInt64) + 1} {
		source := organizationpg.RoleBindingRevokeOperationLookupMigrationSource{Version: version}
		steps, err := source.Load(t.Context())
		valid := version > 0 && version <= migrations.Version(math.MaxInt64)
		if valid && (err != nil || len(steps) != 1) || !valid && (!errors.Is(err, organization.ErrInvalidInput) || len(steps) != 0) {
			t.Fatal("invalid migration version semantics", err)
		}
		if _, err := source.Load(nil); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("nil migration context admitted", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := source.Load(ctx); valid && !errors.Is(err, context.Canceled) {
			t.Fatal("migration cancellation ignored", err)
		}
	}
}

func TestDirectRoleBindingOperationRequiresNativeCustody(t *testing.T) {
	var absent *organizationpg.OperationService
	for _, source := range []*organizationpg.OperationService{absent, {}} {
		op, ok := any(source).(directRoleBindingOperation)
		if !ok {
			t.Fatal("native keyed direct-role assignment and natural exact-binding revocation missing")
		}
		if out, err := op.AssignDynamicRole(t.Context(), organization.AssignDynamicRoleOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero owner manufactured direct role assignment", err)
		}
		if out, err := op.RevokeDynamicRole(t.Context(), organization.RevokeDynamicRoleOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero owner manufactured direct role revocation", err)
		}
	}
}
