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

// Credentials are issued by the genuine signup/verification/password consumer.
// Listing never accepts a claimed subject or selects a global active account.
func exerciseGenuineOrganizationList(t *testing.T, ctx context.Context, s *organizationpg.Service, owner, member organization.Authentication, memberID identity.UserID) {
	t.Helper()
	created := make([]organization.ID, 0, 3)
	commit := func(p organizationpg.PreparedCommand, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if result, err := s.Execute(ctx, p); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine organization-list setup", err)
		}
	}
	for _, slug := range []string{"listed-first", "listed-second", "listed-third"} {
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		org := organization.ID(id)
		created = append(created, org)
		commit(s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Slug: slug, Name: "Genuine organization list", CorrelationID: "organization-list"}, "127.0.0.1"))
	}
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: created[1], UserID: memberID, OrganizationVersion: 1, Role: organization.RoleMember, CorrelationID: "organization-list"}, "127.0.0.1"))
	collect := func(a organization.Authentication) map[organization.ID]organization.Organization {
		t.Helper()
		request := organization.ListOrganizationsRequest{Authentication: a, Limit: 2, CorrelationID: "organization-list"}
		found := map[organization.ID]organization.Organization{}
		var previous organization.ID
		for range 100 {
			result, err := s.ListOrganizations(ctx, request)
			if err != nil {
				t.Fatal("genuine organization page", err)
			}
			if len(result.Organizations) > 2 {
				t.Fatal("genuine list exceeded requested bound")
			}
			for _, org := range result.Organizations {
				if !org.Active || org.TenantID != a.TenantID || org.ID <= previous || found[org.ID].ID != "" {
					t.Fatal("genuine list lost scope or stable ordering")
				}
				found[org.ID], previous = org, org.ID
			}
			if result.NextCursor == "" {
				return found
			}
			request.Cursor = result.NextCursor
		}
		t.Fatal("genuine listing did not terminate within configured membership cap")
		return nil
	}
	owned, visible := collect(owner), collect(member)
	for i, id := range created {
		if owned[id].ID == "" || (visible[id].ID != "") != (i == 1) {
			t.Fatal("genuine list substituted an arbitrary target or omitted owned organizations")
		}
	}
	commit(s.PrepareLeaveMember(ctx, organization.LeaveRequest{Authentication: member, CommandID: commandID(t), OrganizationID: created[1], OrganizationVersion: 2, CorrelationID: "organization-list"}, "127.0.0.1"))
	if collect(member)[created[1]].ID != "" {
		t.Fatal("genuine departed membership still visible")
	}
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: created[1], UserID: memberID, OrganizationVersion: 3, MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "organization-list"}, "127.0.0.1"))
	if collect(member)[created[1]].Version != 4 {
		t.Fatal("genuine readmission did not refresh visible policy epoch")
	}
	foreign := member
	foreign.TenantID = "another-tenant"
	if result, err := s.ListOrganizations(ctx, organization.ListOrganizationsRequest{Authentication: foreign, Limit: 2, CorrelationID: "organization-list"}); !errors.Is(err, organization.ErrForbidden) || len(result.Organizations) != 0 {
		t.Fatal("genuine bearer listed another tenant", err)
	}
}
