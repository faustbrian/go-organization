//go:build integration

package consumer_test

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOrganizationGenuineSlugAvailabilityConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "slug-available")
}

func exerciseGenuineSlugAvailability(t *testing.T, ctx context.Context, service *organizationpg.Service, owner, reader organization.Authentication, logout reference.SessionService) {
	t.Helper()
	request := organization.SlugAvailableRequest{Authentication: reader, Slug: "genuine-slug", CorrelationID: "genuine-slug"}
	if result, err := service.SlugAvailable(ctx, request); err != nil || !result.Available {
		t.Fatal("genuine authenticated nonmember cannot read a free candidate", err)
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := service.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(id), Name: "Genuine slug", Slug: request.Slug, CorrelationID: "genuine-slug-create"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := service.Execute(ctx, prepared); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("advisory availability reserved the candidate against a real create", err)
	}
	if result, err := service.SlugAvailable(ctx, request); err != nil || result.Available {
		t.Fatal("genuine native read retained positive availability after create", err)
	}
	if _, err := service.Get(ctx, organization.ReadRequest{Authentication: reader, OrganizationID: organization.ID(id), CorrelationID: "genuine-slug-nonmember"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("candidate lookup granted organization membership or discovery", err)
	}
	foreign, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	mismatch := request
	mismatch.Authentication.TenantID = identity.TenantID(foreign)
	if result, err := service.SlugAvailable(ctx, mismatch); !errors.Is(err, organization.ErrForbidden) || result.Available {
		t.Fatal("genuine session crossed tenant scope", err)
	}
	token, err := session.ParseToken(reader.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	// Use the already composed public session owner: no raw session-table write
	// or synthetic authentication projection can establish this withdrawal.
	signedOut, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: reader.TenantID, CommandID: commandID(t), CorrelationID: "genuine-slug-signout", Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{})
	if err != nil || !signedOut.SignedOut || !signedOut.ClearBearer || signedOut.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine native session signout did not commit", err)
	}
	request.Slug = "after-signout"
	if result, err := service.SlugAvailable(ctx, request); !errors.Is(err, organization.ErrForbidden) || result.Available {
		t.Fatal("withdrawn genuine session retained candidate access", err)
	}
	request.Authentication = owner
	if result, err := service.SlugAvailable(ctx, request); err != nil || !result.Available {
		t.Fatal("reader signout withdrew an independent genuine owner session", err)
	}
}
