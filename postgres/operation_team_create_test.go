package postgres_test

import (
	"context"
	"errors"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

type teamCreateOperation interface {
	CreateTeam(context.Context, organization.CreateTeamOperationRequest, string) (organization.StoreResult, error)
}

func TestCreateTeamOperationRequiresNativeCustody(t *testing.T) {
	var absent *organizationpg.OperationService
	for _, source := range []*organizationpg.OperationService{absent, {}} {
		operation, ok := any(source).(teamCreateOperation)
		if !ok {
			t.Fatal("native original-key team creation is missing")
		}
		out, err := operation.CreateTeam(t.Context(), organization.CreateTeamOperationRequest{}, "127.0.0.1")
		if !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero native owner manufactured team authority", err)
		}
	}
}
