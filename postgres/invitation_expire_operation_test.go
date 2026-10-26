package postgres_test

import (
	"context"
	"errors"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

type naturalInvitationExpirer interface {
	Expire(context.Context, organization.InvitationExpireOperationRequest, string) (organization.StoreResult, error)
}

func TestInvitationExpireOperationRequiresNativeCustody(t *testing.T) {
	var absent *organizationpg.InvitationService
	for _, native := range []*organizationpg.InvitationService{absent, {}} {
		expire, ok := any(native).(naturalInvitationExpirer)
		if !ok {
			t.Fatal("native initiating natural-repeat expiry is missing")
		}
		out, err := expire.Expire(t.Context(), organization.InvitationExpireOperationRequest{}, "127.0.0.1")
		if !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("zero native owner manufactured expiry authority", err)
		}
	}
}
