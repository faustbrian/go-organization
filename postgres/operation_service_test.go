package postgres_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOperationServiceRejectsMissingNativeOwners(t *testing.T) {
	if service, err := organizationpg.NewOperationService(nil, organizationpg.OperationServiceConfig{}); service != nil || !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("missing native owner graph accepted", err)
	}
	var service *organizationpg.OperationService
	checks := []func() error{
		func() error {
			_, err := service.Create(t.Context(), organization.CreateOperationRequest{}, "127.0.0.1")
			return err
		},
		func() error {
			_, err := service.Update(t.Context(), organization.UpdateOperationRequest{}, "127.0.0.1")
			return err
		},
		func() error {
			_, err := service.AddMember(t.Context(), organization.AddMemberOperationRequest{}, "127.0.0.1")
			return err
		},
		func() error {
			_, err := service.RemoveMember(t.Context(), organization.RemoveMemberOperationRequest{}, "127.0.0.1")
			return err
		},
		func() error { _, err := service.Get(t.Context(), organization.ReadRequest{}); return err },
		func() error { _, err := service.ListMembers(t.Context(), organization.ReadRequest{}); return err },
		func() error {
			_, err := service.RecoverOperation(t.Context(), organization.OperationRecoveryRequest{})
			return err
		},
	}
	for _, check := range checks {
		if !errors.Is(check(), organization.ErrInvalidInput) {
			t.Fatal("zero facade manufactured operation authority")
		}
	}
	if binding, err := new(organizationpg.Contributor).RestoreRequestKey(t.Context(), kernel.RequestKeyPreparationBinding{}, []byte("unowned")); !errors.Is(err, organization.ErrInvalidInput) || binding.CommandID != "" {
		t.Fatal("ordinary contributor manufactured mapped recovery", err)
	}
}

func TestOperationCustodyIsClosedAndRejectsInvalidKeys(t *testing.T) {
	material := []byte(strings.Repeat("k", 32))
	valid, err := organizationpg.NewOperationCustodyConfig("current", map[string][]byte{"current": material})
	if err != nil {
		t.Fatal(err)
	}
	for _, keys := range []map[string][]byte{nil, {"current": make([]byte, 31)}, {"current": material, "bad key": material}} {
		if _, err := organizationpg.NewOperationCustodyConfig("current", keys); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("invalid key configuration accepted", err)
		}
	}
	for _, value := range []any{valid, organizationpg.OperationService{}, organizationpg.OperationServiceConfig{ConfigurationID: "private-config-marker"}} {
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("implicit runtime custody serialization accepted", err)
		}
		if rendered := fmt.Sprintf("%#v", value); !strings.Contains(rendered, "redacted") || strings.Contains(rendered, "private-config-marker") || strings.Contains(rendered, string(material)) {
			t.Fatal("native runtime diagnostics leaked custody")
		}
		if text, ok := value.(interface{ MarshalText() ([]byte, error) }); !ok {
			t.Fatal("text serialization boundary missing")
		} else if _, err := text.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("implicit text custody export accepted", err)
		}
	}
}
