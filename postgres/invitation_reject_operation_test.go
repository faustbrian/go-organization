package postgres_test

import (
	"context"
	"errors"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

type naturalInvitationRejecter interface {
	Reject(context.Context, organization.InvitationRejectOperationRequest, string) (organization.StoreResult, error)
}

func TestInvitationRejectOperationRequiresNativeCustody(t *testing.T) {
	var absent *organizationpg.InvitationService
	for _, native := range []*organizationpg.InvitationService{absent, {}} {
		reject, ok := any(native).(naturalInvitationRejecter)
		if !ok {
			t.Fatal("native initiating natural-repeat rejection is missing")
		}
		out, err := reject.Reject(t.Context(), organization.InvitationRejectOperationRequest{}, "127.0.0.1")
		if !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero native owner manufactured rejection authority", err)
		}
	}
}
