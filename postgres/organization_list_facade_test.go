package postgres_test

import (
	"errors"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOrganizationListFacadeRejectsUnconfiguredOwners(t *testing.T) {
	for _, facade := range []*organizationpg.OperationService{nil, new(organizationpg.OperationService)} {
		result, err := facade.ListOrganizations(t.Context(), organization.ListOrganizationsRequest{})
		if !errors.Is(err, organization.ErrInvalidInput) || result.Organizations != nil || result.NextCursor != "" {
			t.Fatal("unconfigured native facade disclosed a listing", err)
		}
	}
}
