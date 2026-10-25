package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// Keep the transport consumer independent of concrete native preparations and
// recovery structs. This assertion also supplies an executable pre-facade RED.
type directInvitationAccepter interface {
	Accept(context.Context, organization.InvitationAcceptRequest, string, organization.InvitationAcceptAdmitter) (organization.StoreResult, error)
	RecoverAccept(context.Context, organization.InvitationAcceptRecoveryRequest) (organization.StoreResult, error)
}

func directInvitationAcceptance(t testing.TB, source *organizationpg.InvitationService) directInvitationAccepter {
	t.Helper()
	service, ok := any(source).(directInvitationAccepter)
	if !ok {
		t.Fatal("native invitation acceptance has no neutral once/admission/recovery boundary")
	}
	return service
}

func TestInvitationAcceptanceRequiresActualNativeCustody(t *testing.T) {
	var source *organizationpg.InvitationService
	service := directInvitationAcceptance(t, source)
	called := false
	admit := organization.InvitationAcceptAdmitter(func(context.Context, organization.InvitationAcceptAdmission) error {
		called = true
		return nil
	})
	if out, err := service.Accept(t.Context(), organization.InvitationAcceptRequest{}, "127.0.0.1", admit); !errors.Is(err, organization.ErrInvalidInput) || !reflect.DeepEqual(out, organization.StoreResult{}) || called {
		t.Fatal("missing native owners created admission or execution authority", err)
	}
	if out, err := service.RecoverAccept(t.Context(), organization.InvitationAcceptRecoveryRequest{}); !errors.Is(err, organization.ErrInvalidInput) || !reflect.DeepEqual(out, organization.StoreResult{}) {
		t.Fatal("missing native owners created recovery authority", err)
	}
	service = directInvitationAcceptance(t, new(organizationpg.InvitationService))
	if out, err := service.Accept(nil, organization.InvitationAcceptRequest{}, "127.0.0.1", admit); !errors.Is(err, organization.ErrInvalidInput) || !reflect.DeepEqual(out, organization.StoreResult{}) || called {
		t.Fatal("nil acceptance context invoked admission", err)
	}
	if out, err := service.Accept(t.Context(), organization.InvitationAcceptRequest{}, "127.0.0.1", nil); !errors.Is(err, organization.ErrInvalidInput) || !reflect.DeepEqual(out, organization.StoreResult{}) {
		t.Fatal("missing admission callback became permission", err)
	}
}
