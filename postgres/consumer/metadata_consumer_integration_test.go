//go:build integration

package consumer_test

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// These unchanged private fixture helpers are retained on each side of the
// test-module boundary; they add no production API, store or authority.
// Both actors arrive through the real registration/verification/password flow
// in TestOrganizationGenuinePasswordConsumer; this helper inserts no authority.
func exerciseGenuineMetadata(t *testing.T, ctx context.Context, service *organizationpg.Service, owner, recipient organization.Authentication, recipientID identity.UserID) {
	t.Helper()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org := organization.ID(id)
	commit := func(p organizationpg.PreparedCommand, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if got, err := service.Execute(ctx, p); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine metadata transition did not commit", err)
		}
	}
	commit(service.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Slug: "metadata-consumer", Name: "Metadata consumer", CorrelationID: "genuine-metadata"}, "127.0.0.1"))
	r := organization.UpdateRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, Name: "Owner metadata", Slug: "owner-metadata", CorrelationID: "genuine-metadata"}
	commit(service.PrepareUpdate(ctx, r, "127.0.0.1"))
	commit(service.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, UserID: recipientID, Role: organization.RoleMember, OrganizationVersion: 2, CorrelationID: "genuine-metadata"}, "127.0.0.1"))
	r.Authentication, r.CommandID, r.OrganizationVersion = recipient, commandID(t), 3
	r.Name, r.Slug = "Unauthorized metadata", "unauthorized-metadata"
	if _, err = service.PrepareUpdate(ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("genuine member updated metadata", err)
	}
	commit(service.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, UserID: recipientID, OrganizationVersion: 3, MemberVersion: 1, CorrelationID: "genuine-metadata"}, "127.0.0.1"))
	commit(service.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, UserID: recipientID, Role: organization.RoleAdministrator, OrganizationVersion: 4, MemberVersion: 2, CorrelationID: "genuine-metadata"}, "127.0.0.1"))
	r.CommandID, r.OrganizationVersion, r.Name, r.Slug = commandID(t), 5, "Administrator metadata", "administrator-metadata"
	prepared, err := service.PrepareUpdate(ctx, r, "127.0.0.1")
	commit(prepared, err)
	view, err := service.Get(ctx, organization.ReadRequest{Authentication: recipient, OrganizationID: org, CorrelationID: "genuine-metadata"})
	if err != nil || view.Organization.Name != r.Name || view.Organization.Slug != r.Slug || view.Organization.Version != 6 || view.Actor.Role != organization.RoleAdministrator || view.Actor.Version != 3 || view.Actor.AuthorizationVersion != 3 {
		t.Fatal("genuine administrator metadata/read/version contract failed", err)
	}
	recovery, err := prepared.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Recover(ctx, recipient, recovery)
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.BeforeVersion != 5 || got.Receipt.Feature.AfterVersion != 6 {
		t.Fatal("genuine metadata recovery failed", err)
	}
}
