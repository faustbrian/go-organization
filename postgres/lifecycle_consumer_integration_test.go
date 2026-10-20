//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestOrganizationGenuineLifecycleConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "lifecycle")
}

type lifecycleConsumer struct {
	newService func() *organizationpg.Service
	proof      func(organization.Authentication, organization.Operation) auth.ReauthenticationProof
	member     organization.Authentication
	memberID   identity.UserID
}

// All three accounts, sessions, action proofs and invitation capabilities are
// issued by the actual public signup/verification/signin/password/delivery graph.
// The old invitation deadline below is a controlled primary-data setup, not a
// fabricated grant; archive must cancel even naturally expired retained rows.
func exerciseGenuineLifecycle(t *testing.T, ctx context.Context, pool *database.Pool, s *organizationpg.Service, invitations *organizationpg.InvitationService, owner, recipient organization.Authentication, recipientID identity.UserID, signinOwner func() organization.Authentication, expired issued, send func(organization.ID, uint64) issued, profile *lifecycleConsumer) {
	if profile == nil {
		t.Fatal("missing actual lifecycle composition")
	}
	org := expired.org
	commit := func(p organizationpg.PreparedCommand, e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
		got, e := s.Execute(ctx, p)
		if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine lifecycle child commit", e)
		}
	}
	current := func() organization.View {
		t.Helper()
		v, e := s.GetLifecycle(ctx, organization.ReadRequest{Authentication: owner, OrganizationID: org, CorrelationID: "lifecycle"})
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	newID := func() organization.ID {
		t.Helper()
		id, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		return organization.ID(id)
	}
	// Applying/replaying the additive migration above preserved this populated
	// organization and genuine pending invitation; no child authority was invented.
	if v := current(); v.Organization.Version != 1 || v.LifecycleState != organization.LifecycleActive {
		t.Fatal("populated lifecycle upgrade rewrote organization")
	}
	if _, e := pool.Raw().Exec(ctx, `UPDATE organization.invitations SET created_at=date_trunc('second',clock_timestamp())-interval '2 hours',expires_at=date_trunc('second',clock_timestamp())-interval '1 hour' WHERE tenant_id=$1 AND invitation_id=$2`, string(owner.TenantID), string(expired.id)); e != nil {
		t.Fatal(e)
	}
	canceled := send(org, current().Organization.Version)
	cancel, e := invitations.PrepareCancel(ctx, organization.InvitationCancelRequest{Authentication: owner, CommandID: commandID(t), ID: canceled.id, OrganizationID: org, OrganizationVersion: current().Organization.Version, InvitationVersion: 1, CorrelationID: "lifecycle"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if got, e := invitations.Execute(ctx, cancel); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal(e)
	}
	live := send(org, current().Organization.Version)
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: current().Organization.Version, UserID: profile.memberID, Role: organization.RoleMember, CorrelationID: "lifecycle"}, "127.0.0.1"))
	team, role, deletedTeam, deletedRole, claim := newID(), newID(), newID(), newID(), newID()
	for _, id := range []organization.ID{team, deletedTeam} {
		commit(s.PrepareCreateTeam(ctx, organization.CreateTeamRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: current().Organization.Version, TeamID: id, Name: "Engineering", CorrelationID: "lifecycle"}, "127.0.0.1"))
	}
	for _, id := range []organization.ID{role, deletedRole} {
		commit(s.PrepareCreateDynamicRole(ctx, organization.DynamicRoleRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: current().Organization.Version, RoleID: id, Name: "Reader", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}}, CorrelationID: "lifecycle"}, "127.0.0.1"))
	}
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: current().Organization.Version, UserID: recipientID, Role: organization.RoleMember, CorrelationID: "lifecycle"}, "127.0.0.1"))
	removed, e := s.GetDynamicRole(ctx, organization.DynamicRoleReadRequest{Authentication: owner, OrganizationID: org, RoleID: role, TargetUserID: recipientID, CorrelationID: "lifecycle"})
	if e != nil {
		t.Fatal(e)
	}
	commit(s.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: removed.Organization.Version, UserID: recipientID, MemberVersion: removed.Target.Version, CorrelationID: "lifecycle"}, "127.0.0.1"))
	q := organization.DynamicRoleReadRequest{Authentication: owner, OrganizationID: org, RoleID: role, TargetTeamID: team, CorrelationID: "lifecycle"}
	v, e := s.GetDynamicRole(ctx, q)
	if e != nil {
		t.Fatal(e)
	}
	userQ := q
	userQ.TargetTeamID = ""
	userQ.TargetUserID = profile.memberID
	u, e := s.GetDynamicRole(ctx, userQ)
	if e != nil {
		t.Fatal(e)
	}
	commit(s.PrepareAddTeamMember(ctx, organization.TeamMemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: v.Organization.Version, TeamID: team, TeamVersion: v.Team.Version, UserID: profile.memberID, OrganizationMemberVersion: u.Target.Version, CorrelationID: "lifecycle"}, "127.0.0.1"))
	v, e = s.GetDynamicRole(ctx, q)
	if e != nil {
		t.Fatal(e)
	}
	commit(s.PrepareAssignTeamDynamicRole(ctx, organization.TeamRoleBindingRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: v.Organization.Version, TeamID: team, TeamVersion: v.Team.Version, RoleID: role, RoleVersion: v.DynamicRole.Version, BindingVersion: v.TeamRoleBinding.Version, CorrelationID: "lifecycle"}, "127.0.0.1"))
	dt, e := s.GetTeam(ctx, organization.TeamReadRequest{Authentication: owner, OrganizationID: org, TeamID: deletedTeam, CorrelationID: "lifecycle"})
	if e != nil {
		t.Fatal(e)
	}
	commit(s.PrepareDeleteTeam(ctx, organization.DeleteTeamRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: dt.Organization.Version, TeamID: deletedTeam, TeamVersion: dt.Team.Version, CorrelationID: "lifecycle"}, "127.0.0.1"))
	dr, e := s.GetDynamicRole(ctx, organization.DynamicRoleReadRequest{Authentication: owner, OrganizationID: org, RoleID: deletedRole, CorrelationID: "lifecycle"})
	if e != nil {
		t.Fatal(e)
	}
	commit(s.PrepareDeleteDynamicRole(ctx, organization.DynamicRoleRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: dr.Organization.Version, RoleID: deletedRole, RoleVersion: dr.DynamicRole.Version, CorrelationID: "lifecycle"}, "127.0.0.1"))
	domain := "org-" + strings.ReplaceAll(strings.ToLower(string(claim)), "_", "x") + ".example.invalid"
	commit(s.PrepareReserveDomain(ctx, organization.DomainClaimRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: current().Organization.Version, ClaimID: claim, Domain: domain, CorrelationID: "lifecycle"}, "127.0.0.1"))
	dc, e := s.GetDomainClaim(ctx, organization.DomainClaimReadRequest{Authentication: owner, OrganizationID: org, ClaimID: claim, CorrelationID: "lifecycle"})
	if e != nil {
		t.Fatal(e)
	}
	commit(s.PrepareWithdrawDomain(ctx, organization.DomainClaimRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: dc.Organization.Version, ClaimID: claim, ClaimVersion: dc.DomainClaim.Version, Domain: domain, CorrelationID: "lifecycle"}, "127.0.0.1"))
	check := func(want authorization.Outcome) {
		t.Helper()
		d, e := s.CheckPermission(ctx, organization.PermissionCheckRequest{Authentication: profile.member, OrganizationID: org, OrganizationVersion: current().Organization.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "lifecycle"})
		if e != nil || d.Outcome != want {
			t.Fatal("genuine current effective permission", d.Outcome, e)
		}
	}
	check(authorization.Allow)
	before := current()
	beforeAccept, e := invitations.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: live.id, OrganizationID: org, OrganizationVersion: before.Organization.Version, InvitationVersion: 1, Proof: live.proof, CorrelationID: "lifecycle"}, "127.0.0.1")
	if e != nil {
		t.Fatal("positive pending invitation cannot prepare immediately before archive", e)
	}
	archiveProof := profile.proof(owner, organization.Archive)
	archive, e := s.PrepareArchive(ctx, organization.LifecycleRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: before.Organization.Version, Reason: "maintenance", CorrelationID: "lifecycle", Proof: archiveProof}, "127.0.0.1")
	commit(archive, e)
	assertLifecycleProofConsumed(t, ctx, pool, archiveProof, archive, organization.Archive)
	archived := current()
	if archived.Organization.Active || archived.Organization.Version != before.Organization.Version+1 {
		t.Fatal("genuine archive did not advance denying authority")
	}
	if _, e := s.CheckPermission(ctx, organization.PermissionCheckRequest{Authentication: profile.member, OrganizationID: org, OrganizationVersion: archived.Organization.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "lifecycle"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("warm team permission survived archive", e)
	}
	if got, e := invitations.Execute(ctx, beforeAccept); e == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("prepared invitation created authority during archive", e)
	}
	if _, e := s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: archived.Organization.Version, UserID: recipientID, Role: organization.RoleMember, CorrelationID: "lifecycle"}, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("archive admitted new member", e)
	}
	var expiredCanceled, allCanceled bool
	if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT state='cancelled' AND cancelled_at>=expires_at FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$3),bool_and(state='cancelled' AND version=issued_version+1) FROM organization.invitations WHERE tenant_id=$1 AND organization_id=$2`, string(owner.TenantID), string(org), string(expired.id)).Scan(&expiredCanceled, &allCanceled); e != nil || !expiredCanceled || !allCanceled {
		t.Fatal("archive did not terminally cancel expired/live pending invitations at real time", e)
	}
	owner = signinOwner()
	s = profile.newService()
	archived = current()
	if got, e := s.Recover(ctx, owner, mustRoleRecovery(t, archive)); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("fresh genuine archived owner original recovery", e)
	}
	restoreProof := profile.proof(owner, organization.Restore)
	restored, e := s.PrepareRestore(ctx, organization.LifecycleRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: archived.Organization.Version, Reason: "reopened", CorrelationID: "lifecycle", Proof: restoreProof}, "127.0.0.1")
	commit(restored, e)
	assertLifecycleProofConsumed(t, ctx, pool, restoreProof, restored, organization.Restore)
	check(authorization.Allow)
	if _, e := invitations.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: live.id, OrganizationID: org, OrganizationVersion: current().Organization.Version, InvitationVersion: 1, Proof: live.proof, CorrelationID: "lifecycle"}, "127.0.0.1"); e == nil {
		t.Fatal("restoration resurrected canceled original capability", e)
	}
	if _, e := s.Get(ctx, organization.ReadRequest{Authentication: recipient, OrganizationID: org, CorrelationID: "lifecycle"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("restoration revived removed membership", e)
	}
	if _, e := s.GetTeam(ctx, organization.TeamReadRequest{Authentication: owner, OrganizationID: org, TeamID: deletedTeam, CorrelationID: "lifecycle"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("restoration resurrected deleted team", e)
	}
	if _, e := s.GetDynamicRole(ctx, organization.DynamicRoleReadRequest{Authentication: owner, OrganizationID: org, RoleID: deletedRole, CorrelationID: "lifecycle"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("restoration resurrected deleted role", e)
	}
	dc, e = s.GetDomainClaim(ctx, organization.DomainClaimReadRequest{Authentication: owner, OrganizationID: org, ClaimID: claim, CorrelationID: "lifecycle"})
	if e != nil || dc.DomainClaim.State != organization.DomainWithdrawn {
		t.Fatal("restoration resurrected withdrawn domain", e)
	}
}
