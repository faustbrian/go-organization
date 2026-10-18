//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// All sessions come from the actual signup/verification/password-signin owner.
// The departing member supplies no target or administrative credential.
func exerciseGenuineSelfLeave(t *testing.T, ctx context.Context, s *organizationpg.Service, owner, member organization.Authentication, memberID identity.UserID, signinMember func() organization.Authentication) {
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
		if r, err := s.Execute(ctx, p); err != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine leave consumer mutation", err)
		}
	}
	commit(s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Self leave", Slug: "self-leave", CorrelationID: "self-leave"}, "127.0.0.1"))
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: organization.RoleMember, CorrelationID: "self-leave"}, "127.0.0.1"))
	p, err := s.PrepareLeaveMember(ctx, organization.LeaveRequest{Authentication: member, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 2, CorrelationID: "self-leave"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handle, err := p.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	if handle.Binding.UserID != memberID || string(handle.Binding.ActorID) != string(memberID) || handle.Binding.OperationID != string(organization.LeaveMember) {
		t.Fatal("genuine self leave changed subject")
	}
	commit(p, nil)
	q := organization.ReadRequest{Authentication: member, OrganizationID: org, CorrelationID: "self-leave"}
	if _, err = s.Get(ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("genuine departed member retained organization access", err)
	}
	q.Limit = 10
	if _, err = s.ListMembers(ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("genuine departed member retained member list", err)
	}
	fresh := signinMember()
	if fresh.Bearer.Token() == member.Bearer.Token() {
		t.Fatal("leave recovery reused original session")
	}
	if _, err = s.Recover(ctx, fresh, handle); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("fresh global session bypassed current membership disclosure", err)
	}
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 3, UserID: memberID, Role: organization.RoleMember, MemberVersion: 2, CorrelationID: "self-leave"}, "127.0.0.1"))
	got, err := s.Recover(ctx, fresh, handle)
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
		t.Fatal("genuine readmitted member exact metadata recovery", err)
	}
	if _, err = s.PrepareLeaveMember(ctx, organization.LeaveRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 4, CorrelationID: "self-leave"}, "127.0.0.1"); !errors.Is(err, organization.ErrLastOwner) {
		t.Fatal("genuine final recovery owner can leave", err)
	}
}
