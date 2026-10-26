package postgres_test

import (
	"context"
	"errors"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

type teamLifecycleOperation interface {
	UpdateTeam(context.Context, organization.UpdateTeamOperationRequest, string) (organization.StoreResult, error)
	DeleteTeam(context.Context, organization.DeleteTeamOperationRequest, string) (organization.StoreResult, error)
	GetTeam(context.Context, organization.TeamReadRequest) (organization.View, error)
}

func TestTeamLifecycleOperationRequiresNativeCustody(t *testing.T) {
	var absent *organizationpg.OperationService
	for _, source := range []*organizationpg.OperationService{absent, {}} {
		op, ok := any(source).(teamLifecycleOperation)
		if !ok {
			t.Fatal("native original-key team rename and natural terminal delete missing")
		}
		if out, err := op.UpdateTeam(t.Context(), organization.UpdateTeamOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero owner manufactured team rename", err)
		}
		if out, err := op.DeleteTeam(t.Context(), organization.DeleteTeamOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero owner manufactured team deletion", err)
		}
		if _, err := op.GetTeam(t.Context(), organization.TeamReadRequest{}); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("zero owner manufactured team read", err)
		}
	}
}
