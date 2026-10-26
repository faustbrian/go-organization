package postgres_test

import (
	"context"
	"errors"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

type teamMemberOperation interface {
	AddTeamMember(context.Context, organization.AddTeamMemberOperationRequest, string) (organization.StoreResult, error)
	RemoveTeamMember(context.Context, organization.RemoveTeamMemberOperationRequest, string) (organization.StoreResult, error)
	ListMyTeams(context.Context, organization.TeamReadRequest) (organization.View, error)
	ListTeamMembers(context.Context, organization.TeamReadRequest) (organization.View, error)
}

func TestTeamMemberOperationRequiresNativeCustody(t *testing.T) {
	var absent *organizationpg.OperationService
	for _, source := range []*organizationpg.OperationService{absent, {}} {
		op, ok := any(source).(teamMemberOperation)
		if !ok {
			t.Fatal("native original-key admission and natural exact-binding removal missing")
		}
		if out, err := op.AddTeamMember(t.Context(), organization.AddTeamMemberOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero owner manufactured admission", err)
		}
		if out, err := op.RemoveTeamMember(t.Context(), organization.RemoveTeamMemberOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero owner manufactured removal", err)
		}
		if _, err := op.ListMyTeams(t.Context(), organization.TeamReadRequest{}); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("zero owner manufactured teams", err)
		}
		if _, err := op.ListTeamMembers(t.Context(), organization.TeamReadRequest{}); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("zero owner manufactured team members", err)
		}
	}
}
