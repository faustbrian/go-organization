package postgres_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestInvitationServiceRejectsMissingOwnedGraph(t *testing.T) {
	if service, err := organizationpg.NewInvitationService(nil, organizationpg.InvitationServiceConfig{}); service != nil || !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("missing native authority graph admitted", err)
	}
}

func TestInvitationPublicZeroValuesAndSensitiveCustody(t *testing.T) {
	var service organizationpg.InvitationService
	var prepared organizationpg.PreparedInvitation
	if _, err := service.Execute(t.Context(), prepared); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero preparation became execution authority", err)
	}
	if _, err := prepared.Recovery(); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero preparation manufactured recovery scope", err)
	}
	for _, value := range []any{organizationpg.InvitationServiceConfig{}, organizationpg.InvitationDeliveryConfig{Endpoint: "private-config-marker"}, service, prepared} {
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("implicit native custody export admitted", err)
		}
		if rendered := fmt.Sprintf("%#v", value); !strings.Contains(rendered, "redacted") || strings.Contains(rendered, "private-config-marker") {
			t.Fatal("native custody formatting exposed configuration")
		}
	}
}

func TestInvitationResendPublicBoundaryRejectsMissingCustody(t *testing.T) {
	var service *organizationpg.InvitationService
	if _, err := service.PrepareResend(t.Context(), organization.InvitationResendRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("missing resend service admitted", err)
	}
	result, err := service.ExecuteResend(t.Context(), organizationpg.PreparedInvitation{})
	if !errors.Is(err, organization.ErrInvalidInput) || result.Delivery != nil {
		t.Fatal("missing resend custody manufactured a delivery observation", err)
	}
	result, err = service.RecoverResend(t.Context(), organization.Authentication{}, organizationpg.InvitationRecovery{})
	if !errors.Is(err, organization.ErrInvalidInput) || result.Delivery != nil {
		t.Fatal("missing original command manufactured resend history", err)
	}
}
