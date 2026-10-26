package postgres_test

import (
	"errors"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestLeaveOperationRejectsMissingNativeOwner(t *testing.T) {
	for _, service := range []*organizationpg.OperationService{nil, {}} {
		if _, err := service.LeaveMember(t.Context(), organization.LeaveMemberOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("zero leave facade accepted missing owner", err)
		}
	}
}
