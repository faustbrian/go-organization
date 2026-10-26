package postgres_test

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

type dynamicRoleOperation interface {
	CreateDynamicRole(context.Context, organization.CreateDynamicRoleOperationRequest, string) (organization.StoreResult, error)
	UpdateDynamicRole(context.Context, organization.UpdateDynamicRoleOperationRequest, string) (organization.StoreResult, error)
	DeleteDynamicRole(context.Context, organization.DeleteDynamicRoleOperationRequest, string) (organization.StoreResult, error)
	GetDynamicRole(context.Context, organization.DynamicRoleReadRequest) (organization.View, error)
	ListDynamicRoles(context.Context, organization.DynamicRoleReadRequest) (organization.View, error)
	CheckPermission(context.Context, organization.PermissionCheckRequest) (authorization.Decision, error)
}

func TestDynamicRoleOperationLookupMigrationBounds(t *testing.T) {
	for _, version := range []migrations.Version{0, 1, migrations.Version(math.MaxInt64), migrations.Version(math.MaxInt64) + 1} {
		source := organizationpg.DynamicRoleDeleteOperationLookupMigrationSource{Version: version}
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

func TestDynamicRoleOperationRequiresNativeCustody(t *testing.T) {
	var absent *organizationpg.OperationService
	for _, source := range []*organizationpg.OperationService{absent, {}} {
		op, ok := any(source).(dynamicRoleOperation)
		if !ok {
			t.Fatal("native keyed role CRUD, natural terminal delete and effective permission facade missing")
		}
		if out, err := op.CreateDynamicRole(t.Context(), organization.CreateDynamicRoleOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero owner manufactured custom role creation", err)
		}
		if out, err := op.UpdateDynamicRole(t.Context(), organization.UpdateDynamicRoleOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero owner manufactured custom role replacement", err)
		}
		if out, err := op.DeleteDynamicRole(t.Context(), organization.DeleteDynamicRoleOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero owner manufactured custom role retirement", err)
		}
		if _, err := op.GetDynamicRole(t.Context(), organization.DynamicRoleReadRequest{}); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("zero owner manufactured exact role read", err)
		}
		if _, err := op.ListDynamicRoles(t.Context(), organization.DynamicRoleReadRequest{}); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("zero owner manufactured role list", err)
		}
		if out, err := op.CheckPermission(t.Context(), organization.PermissionCheckRequest{}); !errors.Is(err, organization.ErrInvalidInput) || !reflect.DeepEqual(out, authorization.Decision{}) {
			t.Fatal("zero owner manufactured permission decision", err)
		}
	}
}
