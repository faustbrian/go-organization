//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// Every credential is actually issued by the signup/verification/password
// consumer; recoveryOwner is another genuine session of the same source user.
func exerciseGenuineOwnerTransfer(t *testing.T, ctx context.Context, s *organizationpg.Service, owner, member, recoveryOwner organization.Authentication, memberID identity.UserID, proof auth.ReauthenticationProof) {
	t.Helper()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org := organization.ID(id)
	commit := func(p organizationpg.PreparedCommand, err error) organization.StoreResult {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Execute(ctx, p)
		if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine transfer consumer mutation", err)
		}
		return got
	}
	commit(s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Transfer ownership", Slug: "owner-transfer", CorrelationID: "transfer"}, "127.0.0.1"))
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: organization.RoleMember, CorrelationID: "transfer"}, "127.0.0.1"))
	p, err := s.PrepareOwnerTransfer(ctx, organization.OwnerTransferRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 2, SourceVersion: 1, TargetUserID: memberID, TargetVersion: 1, CorrelationID: "transfer", Proof: proof}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handle, err := p.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(handle)
	if err != nil {
		t.Fatal(err)
	}
	var restored organizationpg.Recovery
	if err = json.Unmarshal(wire, &restored); err != nil {
		t.Fatal(err)
	}
	commit(p, nil)
	if recoveryOwner.Bearer.Token() == owner.Bearer.Token() {
		t.Fatal("transfer recovery requires separately issued genuine source session")
	}
	for range 2 {
		got, err := s.Recover(ctx, recoveryOwner, restored)
		if err != nil || got.Receipt.Binding != handle.Binding || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine former-owner metadata recovery", err)
		}
	}
	view, err := s.ListMembers(ctx, organization.ReadRequest{Authentication: member, OrganizationID: org, Limit: 10, CorrelationID: "transfer"})
	if err != nil || view.Organization.Version != 3 || view.Actor.Role != organization.RoleOwner || view.Actor.Version != 2 || len(view.Members) != 2 {
		t.Fatal("genuine transferred owner cannot read current state", err)
	}
	if _, err = s.PrepareOwnerTransfer(ctx, organization.OwnerTransferRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 3, SourceVersion: 2, TargetUserID: memberID, TargetVersion: 2, CorrelationID: "transfer", Proof: proof}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("genuine former owner retained privilege", err)
	}
	if _, err = s.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: member, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 3, UserID: memberID, MemberVersion: 2, CorrelationID: "transfer"}, "127.0.0.1"); !errors.Is(err, organization.ErrLastOwner) {
		t.Fatal("genuine transferred last owner can be removed", err)
	}
}
