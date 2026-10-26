package postgres_test

import (
	"context"
	"errors"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestSlugAvailabilityRejectsUnconfiguredNativeOwners(t *testing.T) {
	var service *organizationpg.Service
	if result, err := service.SlugAvailable(context.Background(), organization.SlugAvailableRequest{}); !errors.Is(err, organization.ErrInvalidInput) || result.Available {
		t.Fatal("nil native service disclosed availability", err)
	}
	var repository *organizationpg.Repository
	if result, err := repository.ReadOrganizationSlug(context.Background(), organization.OrganizationSlugQuery{TenantID: "tenant", Slug: "candidate"}); !errors.Is(err, organization.ErrInvalidInput) || result.Available {
		t.Fatal("nil native repository disclosed availability", err)
	}
	for _, operation := range []*organizationpg.OperationService{nil, new(organizationpg.OperationService)} {
		if result, err := operation.SlugAvailable(context.Background(), organization.SlugAvailableRequest{}); !errors.Is(err, organization.ErrInvalidInput) || result.Available {
			t.Fatal("unconfigured operation facade disclosed availability", err)
		}
	}
}
