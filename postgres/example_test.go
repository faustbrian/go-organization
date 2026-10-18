package postgres_test

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// createOrganization illustrates the public boundary after constructing the
// real migrated native composition described in README.md. Production callers
// durably retain recovery before Execute and reconcile Unknown outcomes.
func createOrganization(ctx context.Context, service *organizationpg.Service, auth organization.Authentication, id organization.ID, command identity.CommandID) (organization.StoreResult, organizationpg.Recovery, error) {
	p, e := service.PrepareCreate(ctx, organization.CreateRequest{Authentication: auth, CommandID: command, ID: id, Slug: "example", Name: "Example", CorrelationID: "create-example"}, "127.0.0.1")
	if e != nil {
		return organization.StoreResult{}, organizationpg.Recovery{}, e
	}
	r, e := p.Recovery()
	if e != nil {
		return organization.StoreResult{}, organizationpg.Recovery{}, e
	}
	out, e := service.Execute(ctx, p)
	return out, r, e
}

func ExamplePreparedCommand_Recovery() {
	_, e := (organizationpg.PreparedCommand{}).Recovery()
	fmt.Println(e == organization.ErrInvalidInput)
	// Output: true
}
