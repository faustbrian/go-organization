//go:build integration

package consumer_test

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

func TestOrganizationGenuineDomainEvidenceConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "domain-evidence")
}

func exerciseGenuineDomainEvidence(t *testing.T, ctx context.Context, db *sql.DB, s *organizationpg.Service, owner, member, recoveryOwner organization.Authentication, memberID identity.UserID, observer *nativeDomainObserver) {
	t.Helper()
	var steps migrationList
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.DomainClaimMigrationSource{Version: 7010}, organizationpg.DomainEvidenceMigrationSource{Version: 7011}} {
		more, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		steps = append(steps, more...)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(steps, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	newID := func() organization.ID {
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		return organization.ID(id)
	}
	org, claim := newID(), newID()
	commit := func(p organizationpg.PreparedCommand, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if r, err := s.Execute(ctx, p); err != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine evidence prerequisite", err)
		}
	}
	commit(s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Slug: "genuine-evidence", Name: "Genuine evidence", CorrelationID: "evidence"}, "127.0.0.1"))
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: organization.RoleMember, CorrelationID: "evidence"}, "127.0.0.1"))
	r := organization.DomainClaimRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 2, ClaimID: claim, Domain: "genuine-proof.example", CorrelationID: "evidence"}
	commit(s.PrepareReserveDomain(ctx, r, "127.0.0.1"))
	authority, err := s.DomainEvidence(owner, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	r.CommandID = commandID(t)
	r.OrganizationVersion = 3
	r.ClaimVersion = 1
	command, err := authority.Prepare(ctx, organization.DomainEvidenceRequest{Claim: r})
	if err != nil {
		t.Fatal(err)
	}
	original, err := authority.ApplyDomainEvidence(ctx, command)
	if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine attributable apply", err)
	}
	key := organization.DomainProofKey(original.Proof)
	if p, err := authority.GetDomainProof(ctx, key); err != nil || p != original.Proof {
		t.Fatal("genuine current authoritative proof", err)
	}
	if owner.Bearer.Token() == recoveryOwner.Bearer.Token() {
		t.Fatal("recovery did not use fresh genuine signin")
	}
	recovery, err := s.DomainEvidence(recoveryOwner, "127.0.0.1", evidenceRecovery(t, command))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := recovery.RecoverDomainEvidence(ctx, r.CommandID)
	if err != nil || recovered.Proof != original.Proof || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted || observer.calls.Load() != 1 {
		t.Fatal("genuine exact recovery changed observation", err)
	}
	denied, err := s.DomainEvidence(member, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = denied.GetDomainProof(ctx, key); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("member-only proof disclosure", err)
	}
	revoker, err := s.DomainEvidence(recoveryOwner, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	r.CommandID = commandID(t)
	r.OrganizationVersion = 4
	revoke, err := revoker.PrepareRevocation(ctx, organization.DomainEvidenceRequest{Claim: r, ProofVersion: 1}, key)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := revoker.ApplyDomainEvidence(ctx, revoke)
	if err != nil || !terminal.Proof.Revoked || terminal.Proof.ExpiresAt != original.Proof.ExpiresAt {
		t.Fatal("genuine terminal revocation", err)
	}
	if _, err = recovery.GetDomainProof(ctx, key); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("genuine revoked proof stayed current", err)
	}
	recovered, err = recovery.RecoverDomainEvidence(ctx, original.Receipt.Binding.CommandID)
	if err != nil || recovered.Proof != original.Proof || observer.calls.Load() != 1 {
		t.Fatal("genuine revocation changed historical proof", err)
	}
}
