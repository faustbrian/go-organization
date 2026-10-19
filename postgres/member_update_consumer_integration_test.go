//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

// Every bearer here is issued by real registration, verification and password
// signin. Only the explicitly named commit-response transport fault is synthetic.
func exerciseGenuineMemberRoleUpdate(t *testing.T, ctx context.Context, pool *database.Pool, s *organizationpg.Service, sessions *session.SessionService, owner, member organization.Authentication, ownerID, memberID identity.UserID, signinMember, signinOwner func() organization.Authentication, newService func(*database.Pool) *organizationpg.Service) {
	t.Helper()
	commit := func(p organizationpg.PreparedCommand, err error) organizationpg.PreparedCommand {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Execute(ctx, p)
		if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine role mutation failed", err)
		}
		return p
	}
	newOrg := func(slug string) organization.ID {
		t.Helper()
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		org := organization.ID(id)
		commit(s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Slug: slug, Name: "Role update", CorrelationID: "member-role"}, "127.0.0.1"))
		commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: organization.RoleMember, CorrelationID: "member-role"}, "127.0.0.1"))
		return org
	}
	request := func(org organization.ID, a organization.Authentication, target identity.UserID, epoch, version uint64, role organization.Role) organization.MemberRequest {
		return organization.MemberRequest{Authentication: a, CommandID: commandID(t), OrganizationID: org, UserID: target, OrganizationVersion: epoch, MemberVersion: version, Role: role, CorrelationID: "member-role"}
	}
	org := newOrg("genuine-role")
	other := newOrg("independent-role")
	p := commit(s.PrepareUpdateMember(ctx, request(org, owner, memberID, 2, 1, organization.RoleAdministrator), "127.0.0.1"))
	commit(p, nil)
	view, err := s.ListMembers(ctx, organization.ReadRequest{Authentication: member, OrganizationID: org, Limit: 10, CorrelationID: "member-role"})
	if err != nil || view.Organization.Version != 3 || view.Actor.Role != organization.RoleAdministrator || view.Actor.Version != 2 || view.Actor.AuthorizationVersion != 2 || len(view.Members) != 2 {
		t.Fatal("genuine authoritative role projection missing", err)
	}
	// Existing management authorization reads the actual promoted role and the
	// new organization policy epoch, without reissuing the global login session.
	commit(s.PrepareUpdate(ctx, organization.UpdateRequest{Authentication: member, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 3, Name: "Administrator authorized", Slug: "genuine-role-updated", CorrelationID: "member-role"}, "127.0.0.1"))
	if _, err := s.PrepareUpdateMember(ctx, request(org, member, memberID, 4, 2, organization.RoleOwner), "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("genuine administrator self-escalated", err)
	}
	if _, err := s.PrepareUpdateMember(ctx, request(org, member, ownerID, 4, 1, organization.RoleMember), "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("genuine administrator mutated owner", err)
	}
	if _, err := s.PrepareUpdateMember(ctx, request(org, owner, ownerID, 4, 1, organization.RoleAdministrator), "127.0.0.1"); !errors.Is(err, organization.ErrLastOwner) {
		t.Fatal("genuine final recovery owner demoted", err)
	}
	self := commit(s.PrepareUpdateMember(ctx, request(org, member, memberID, 4, 2, organization.RoleMember), "127.0.0.1"))
	commit(self, nil)
	handle, err := self.Recovery()
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
	fresh := signinMember()
	if fresh.Bearer.Token() == member.Bearer.Token() {
		t.Fatal("genuine recovery reused original signin")
	}
	got, err := newService(pool).Recover(ctx, fresh, restored)
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
		t.Fatal("reconstructed self-demotion metadata recovery failed", err)
	}
	// Withdraw only this independently issued session, keeping original active
	// membership and its original login valid to discriminate session admission.
	token, err := session.ParseToken(fresh.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := sessions.Get(ctx, session.GetRequest{TenantID: fresh.TenantID, Credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := observed.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, string(fresh.TenantID), bound.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := newService(pool).Recover(ctx, fresh, restored); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("withdrawn genuine session disclosed self-role history", err)
	}
	got, err = newService(pool).Recover(ctx, member, restored)
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("session withdrawal oracle changed original member authority", err)
	}
	if _, err := s.PrepareUpdate(ctx, organization.UpdateRequest{Authentication: member, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 5, Name: "Forbidden", Slug: "forbidden", CorrelationID: "member-role"}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("genuine demotion retained management permission", err)
	}
	view, err = s.Get(ctx, organization.ReadRequest{Authentication: member, OrganizationID: other, CorrelationID: "member-role"})
	if err != nil || view.Actor.Version != 1 || view.Actor.AuthorizationVersion != 1 || view.Actor.Role != organization.RoleMember || view.Organization.Version != 2 {
		t.Fatal("role update leaked into independent organization/global session", err)
	}
	commit(s.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, UserID: memberID, OrganizationVersion: 5, MemberVersion: 3, CorrelationID: "member-role"}, "127.0.0.1"))
	if _, err := newService(pool).Recover(ctx, member, restored); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("removed genuine self recovered historical privilege", err)
	}
	if _, err := s.Execute(ctx, self); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("removed genuine self replay disclosed outcome", err)
	}
	// A second organization uses a real lost COMMIT response and reconstructs
	// a service and safe handle, never a role/code/proof replay surrogate.
	fault := new(commitResponseLoss)
	faultPool, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &lossyCommitConn{Conn: conn, fault: fault}, nil
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := faultPool.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	faultService := newService(faultPool)
	lost, err := faultService.PrepareUpdateMember(ctx, request(other, owner, memberID, 2, 1, organization.RoleAdministrator), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	lostHandle, err := lost.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	fault.armed.Store(true)
	got, err = faultService.Execute(ctx, lost)
	if err == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown || got.Receipt.Binding != lostHandle.Binding {
		t.Fatal("genuine role lost acknowledgment not unknown", err)
	}
	got, err = newService(pool).Recover(ctx, signinOwner(), lostHandle)
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != lostHandle.Binding {
		t.Fatal("genuine unknown-role commit recovery failed", err)
	}
	var effects int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM organization.command_effects WHERE command_id=$1`, string(lostHandle.Binding.CommandID)).Scan(&effects); err != nil || effects != 1 {
		t.Fatal("role recovery repeated effect", err)
	}
}
