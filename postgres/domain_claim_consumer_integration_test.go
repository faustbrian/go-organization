//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOrganizationGenuineDomainClaimConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "domain")
}

// Reuses the original real registration -> email verification -> password
// signin owner. No test-fabricated principal/session stands in for that journey.
func exerciseGenuineDomainClaims(t *testing.T, ctx context.Context, db *sql.DB, s *organizationpg.Service, owner, member, recoveryOwner organization.Authentication, memberID identity.UserID) {
	t.Helper()
	var steps migrationList
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.DomainClaimMigrationSource{Version: 7010}} {
		more, e := source.Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		steps = append(steps, more...)
	}
	backend, e := migrationpg.New(db)
	if e != nil {
		t.Fatal(e)
	}
	backend, e = backend.ForNamespace("organization")
	if e != nil {
		t.Fatal(e)
	}
	runner, e := migrations.NewRunner(steps, backend)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = runner.Up(ctx); e != nil {
		t.Fatal("populated domain migration", e)
	}
	newID := func() organization.ID {
		id, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		return organization.ID(id)
	}
	org, claim := newID(), newID()
	commit := func(p organizationpg.PreparedCommand, e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
		if got, e := s.Execute(ctx, p); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine domain mutation", e)
		}
	}
	commit(s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Genuine domain custody", Slug: "genuine-domain", CorrelationID: "domain"}, "127.0.0.1"))
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: organization.RoleMember, CorrelationID: "domain"}, "127.0.0.1"))
	r := organization.DomainClaimRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, ClaimID: claim, OrganizationVersion: 2, Domain: "Genuine.Example.", CorrelationID: "domain"}
	p, e := s.PrepareReserveDomain(ctx, r, "127.0.0.1")
	commit(p, e)
	q := organization.DomainClaimReadRequest{Authentication: owner, OrganizationID: org, ClaimID: claim, CorrelationID: "domain-read"}
	v, e := s.GetDomainClaim(ctx, q)
	if e != nil || v.DomainClaim.Domain != "genuine.example" || v.DomainClaim.State != organization.DomainRequested || v.DomainClaim.Version != 1 || v.Organization.Version != 3 {
		t.Fatal("genuine current reservation", e)
	}
	q.Authentication = member
	if _, e = s.GetDomainClaim(ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("member-only custody read", e)
	}
	handle, e := p.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	if owner.Bearer.Token() == recoveryOwner.Bearer.Token() {
		t.Fatal("expected distinct genuine recovery session")
	}
	if got, e := s.Recover(ctx, recoveryOwner, handle); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine fresh-session reservation recovery", e)
	}
	r.CommandID = commandID(t)
	r.OrganizationVersion = 3
	r.ClaimVersion = 1
	p, e = s.PrepareWithdrawDomain(ctx, r, "127.0.0.1")
	commit(p, e)
	q.Authentication = owner
	v, e = s.GetDomainClaim(ctx, q)
	if e != nil || v.DomainClaim.ID != claim || v.DomainClaim.State != organization.DomainWithdrawn || v.DomainClaim.Version != 2 || v.Organization.Version != 4 {
		t.Fatal("genuine immutable withdrawal tombstone", e)
	}
	r.CommandID = commandID(t)
	r.ClaimID = newID()
	r.OrganizationVersion = 4
	r.ClaimVersion = 0
	commit(s.PrepareReserveDomain(ctx, r, "127.0.0.1"))
	v, e = s.GetDomainClaim(ctx, q)
	if e != nil || v.DomainClaim.ID != claim || v.DomainClaim.State != organization.DomainWithdrawn {
		t.Fatal("new reservation resurrected old claim", e)
	}
}
