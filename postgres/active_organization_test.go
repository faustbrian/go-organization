package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	organization "github.com/faustbrian/go-organization"
)

type activeOrganizationNative interface {
	PrepareActiveOrganization(context.Context, organization.ActiveOrganizationRequest, string) (PreparedCommand, error)
	GetActiveOrganization(context.Context, organization.ActiveOrganizationReadRequest) (organization.ActiveOrganizationView, error)
}

type activeOrganizationOperation interface {
	SetActiveOrganization(context.Context, organization.ActiveOrganizationOperationRequest, string) (organization.StoreResult, error)
	GetActiveOrganization(context.Context, organization.ActiveOrganizationReadRequest) (organization.ActiveOrganizationView, error)
}

func TestActiveOrganizationNativeRequiresOwnedComposition(t *testing.T) {
	for _, service := range []*Service{nil, {}} {
		native, ok := any(service).(activeOrganizationNative)
		if !ok {
			t.Fatal("native exact-session selection boundary missing")
		}
		if out, err := native.PrepareActiveOrganization(t.Context(), organization.ActiveOrganizationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (PreparedCommand{}) {
			t.Fatal("missing native owner prepared selection", err)
		}
		if out, err := native.GetActiveOrganization(t.Context(), organization.ActiveOrganizationReadRequest{}); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.ActiveOrganizationView{}) {
			t.Fatal("missing native owner disclosed selection", err)
		}
	}
	for _, service := range []*OperationService{nil, {}} {
		native, ok := any(service).(activeOrganizationOperation)
		if !ok {
			t.Fatal("stable-key native selection boundary missing")
		}
		if out, err := native.SetActiveOrganization(t.Context(), organization.ActiveOrganizationOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out != (organization.StoreResult{}) {
			t.Fatal("missing keyed owner prepared selection", err)
		}
	}
}

func TestActiveOrganizationIntentNamesExactSessionAndAbsence(t *testing.T) {
	r := organization.ActiveOrganizationOperationRequest{SessionID: "session", OrganizationID: "org"}
	before := activeOrganizationIntent(r)
	for _, change := range []func(*organization.ActiveOrganizationOperationRequest){
		func(r *organization.ActiveOrganizationOperationRequest) { r.SessionID = "sibling" },
		func(r *organization.ActiveOrganizationOperationRequest) { r.OrganizationID = "other" },
		func(r *organization.ActiveOrganizationOperationRequest) { r.OrganizationID = "" },
	} {
		copy := r
		change(&copy)
		if reflect.DeepEqual(before, activeOrganizationIntent(copy)) {
			t.Fatal("different selection intent aliases original key")
		}
	}
	r.CorrelationID = "new-diagnostic"
	if !reflect.DeepEqual(before, activeOrganizationIntent(r)) {
		t.Fatal("diagnostic retry changes semantic intent")
	}
}
