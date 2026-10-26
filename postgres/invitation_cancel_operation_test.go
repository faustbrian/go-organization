package postgres_test

import (
	"context"
	"errors"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

type naturalInvitationCanceller interface {
	Cancel(context.Context, organization.InvitationCancelOperationRequest, string) (organization.StoreResult, error)
}

func TestInvitationCancelOperationRequiresNativeCustody(t *testing.T) {
	var absent *organizationpg.InvitationService
	for _, native := range []*organizationpg.InvitationService{absent, {}} {
		cancel, ok := any(native).(naturalInvitationCanceller)
		if !ok {
			t.Fatal("native initiating natural-repeat cancellation is missing")
		}
		out, err := cancel.Cancel(t.Context(), organization.InvitationCancelOperationRequest{}, "127.0.0.1")
		if !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero native owner manufactured cancellation authority", err)
		}
	}
}
