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
