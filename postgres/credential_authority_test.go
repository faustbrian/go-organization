package postgres_test

import (
	"context"
	"errors"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestCredentialAuthorityOwnerOnlyReaderBoundary(t *testing.T) {
	var repository *organizationpg.Repository
	if _, ok := any(repository).(organization.CredentialAuthorityReader); !ok {
		t.Fatal("native repository lacks the owner-only credential authority reader; member-only Read cannot verify an independent organization key")
	}
}

func TestCredentialAuthorityZeroRepositoryReturnsNoFacts(t *testing.T) {
	query := organization.CredentialAuthorityQuery{TenantID: "tenant", OrganizationID: "org"}
	for _, repository := range []*organizationpg.Repository{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			if got, err := repository.ObserveCredentialAuthority(ctx, query); !errors.Is(err, organization.ErrInvalidInput) || got != (organization.CredentialAuthorityObservation{}) {
				t.Fatal("uninitialized reader returned authority", err)
			}
			if err := repository.RequireCredentialAuthority(ctx, kernel.Work{}, nil, organization.CredentialAuthorityObservation{}); !errors.Is(err, organization.ErrInvalidInput) {
				t.Fatal("uninitialized repository accepted Work", err)
			}
		}
	}
}
