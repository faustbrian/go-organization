//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
)

func assertLifecycleProofConsumed(t *testing.T, ctx context.Context, pool *database.Pool, proof auth.ReauthenticationProof, p organizationpg.PreparedCommand, op organization.Operation) {
	t.Helper()
	b := mustRoleRecovery(t, p).Binding
	command, e := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if e != nil {
		t.Fatal(e)
	}
	var consumed bool
	e = pool.Raw().QueryRow(ctx, `SELECT coalesce(consumed_command_id=$4 AND consumed_purpose=$5 AND consumed_at IS NOT NULL,false) FROM identity_password.reauthentication_records WHERE proof_id=$1 AND tenant_id=$2 AND user_id=$3 AND purpose='identity.password.verify'`, string(proof.Proof.ID), string(proof.Proof.Tenant), string(proof.Proof.Subject), command, string(op)).Scan(&consumed)
	if e != nil || !consumed {
		t.Fatal("lifecycle did not consume exact password proof for original command/action", e)
	}
}

func lifecyclePrimaries(t *testing.T, source *passwordpg.ReauthenticationService) (*passwordpg.ActionPrimarySource, *passwordpg.ActionPrimarySource) {
	t.Helper()
	makeSource := func(op organization.Operation) *passwordpg.ActionPrimarySource {
		t.Helper()
		s, e := passwordpg.NewActionPrimarySource(source, passwordpg.ActionPrimaryConfig{Action: string(op), Audience: transferAudience, MaximumAge: 15 * time.Minute, Transport: session.CredentialBearer})
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	return makeSource(organization.Archive), makeSource(organization.Restore)
}

func issueLifecycleProof(t *testing.T, ctx context.Context, source *passwordpg.ReauthenticationService, a organization.Authentication, user identity.UserID, revision uint64, op organization.Operation) auth.ReauthenticationProof {
	t.Helper()
	secret, e := primitive.NewSecret([]byte(transferFixturePassword))
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Destroy()
	// Use the password owner's actual admitted authentication action, risk,
	// verifier and signed record; no visible proof fields are fabricated.
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(revision), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Tenant: authorization.TenantID(a.TenantID), Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}
	got, e := source.Verify(ctx, passwordpg.ReauthenticationRequest{TenantID: a.TenantID, Session: a.Bearer, Password: secret, Target: passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: string(op), Audience: transferAudience}, Caller: caller, Network: "127.0.0.1", Device: "lifecycle-consumer"})
	if e != nil || got.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual lifecycle password verification", e)
	}
	return got.Proof
}

func lifecycleSnapshot(t *testing.T, f *ownerFixture, tenant string) organization.View {
	t.Helper()
	v, e := f.service.GetLifecycle(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, CorrelationID: "lifecycle"})
	if e != nil {
		t.Fatal("lifecycle snapshot", e)
	}
	return v
}

func lifecycleCommand(t *testing.T, f *ownerFixture, tenant string, op organization.Operation) organizationpg.PreparedCommand {
	t.Helper()
	v := lifecycleSnapshot(t, f, tenant)
	r := organization.LifecycleRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: v.Organization.Version, Reason: "maintenance", CorrelationID: "lifecycle", Proof: issueLifecycleProof(t, f.ctx, f.proofOwner, f.auth(tenant, "owner"), identity.UserID(transferUser("owner")), 1, op)}
	var p organizationpg.PreparedCommand
	var e error
	if op == organization.Archive {
		p, e = f.service.PrepareArchive(f.ctx, r, "127.0.0.1")
	} else {
		p, e = f.service.PrepareRestore(f.ctx, r, "127.0.0.1")
	}
	if e != nil {
		t.Fatal("lifecycle prepare", e)
	}
	return p
}

func TestOrganizationLifecycleArchiveRestoreOwnerAndAuthority(t *testing.T) {
	f := newOwnerFixture(t, true)
	tenant := transferTenants["org-test-basic"]
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	archive := lifecycleCommand(t, f, tenant, organization.Archive)
	commitRole(t, f.orgFixture, archive, nil)
	v := lifecycleSnapshot(t, f, tenant)
	if v.LifecycleState != organization.LifecycleArchived || v.Organization.Active || v.Organization.Version != 3 || v.LifecycleReason != "maintenance" {
		t.Fatal("archive state/epoch not committed")
	}
	for _, actor := range []string{"owner", "member"} {
		if _, e := f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, actor), OrganizationID: metadataOrganization, CorrelationID: "archived"}); !errors.Is(e, organization.ErrForbidden) {
			t.Fatal("warm archived organization remained readable", e)
		}
	}
	if _, e := f.service.GetLifecycle(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "member"), OrganizationID: metadataOrganization, CorrelationID: "archived"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("ordinary member discovered archived lifecycle", e)
	}
	for range 2 {
		got, e := f.service.Recover(f.ctx, f.auth(tenant, "owner"), mustRoleRecovery(t, archive))
		if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("owner cannot recover archived original", e)
		}
	}
	restored := lifecycleCommand(t, f, tenant, organization.Restore)
	commitRole(t, f.orgFixture, restored, nil)
	v = lifecycleSnapshot(t, f, tenant)
	if v.LifecycleState != organization.LifecycleActive || !v.Organization.Active || v.Organization.Version != 4 {
		t.Fatal("restore state/epoch not committed")
	}
	if _, e := f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "member"), OrganizationID: metadataOrganization, CorrelationID: "restored"}); e != nil {
		t.Fatal("surviving current member cannot read restored org", e)
	}
}

func TestOrganizationLifecycleConsumesExactActionProofOnce(t *testing.T) {
	f := newOwnerFixture(t, true)
	tenant := transferTenants["org-test-basic"]
	f.create(t, tenant)
	prepare := func(op organization.Operation, proof auth.ReauthenticationProof) organizationpg.PreparedCommand {
		t.Helper()
		v := lifecycleSnapshot(t, f, tenant)
		r := organization.LifecycleRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: v.Organization.Version, Reason: "maintenance", CorrelationID: "proof-consumption", Proof: proof}
		var p organizationpg.PreparedCommand
		var e error
		if op == organization.Archive {
			p, e = f.service.PrepareArchive(f.ctx, r, "127.0.0.1")
		} else {
			p, e = f.service.PrepareRestore(f.ctx, r, "127.0.0.1")
		}
		if e != nil {
			t.Fatal("current owner/session/version cannot prepare proof consumption attempt", e)
		}
		return p
	}
	issue := func(op organization.Operation) auth.ReauthenticationProof {
		return issueLifecycleProof(t, f.ctx, f.proofOwner, f.auth(tenant, "owner"), identity.UserID(transferUser("owner")), 1, op)
	}
	archiveProof := issue(organization.Archive)
	archive := prepare(organization.Archive, archiveProof)
	commitRole(t, f.orgFixture, archive, nil)
	assertLifecycleProofConsumed(t, f.ctx, f.pool, archiveProof, archive, organization.Archive)
	restoreProof := issue(organization.Restore)
	restore := prepare(organization.Restore, restoreProof)
	commitRole(t, f.orgFixture, restore, nil)
	assertLifecycleProofConsumed(t, f.ctx, f.pool, restoreProof, restore, organization.Restore)
	rejectReuse := func(op organization.Operation, proof auth.ReauthenticationProof) {
		t.Helper()
		before := lifecycleSnapshot(t, f, tenant)
		// The state has returned to the action's valid source state. Preparation
		// discovers the current epoch and admits the genuine unchanged session;
		// only the password owner's one-use consumption fence should deny Apply.
		p := prepare(op, proof)
		got, e := f.service.Execute(f.ctx, p)
		if !errors.Is(e, organization.ErrForbidden) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("consumed lifecycle proof committed under a new command", e)
		}
		if after := lifecycleSnapshot(t, f, tenant); after.Organization != before.Organization || after.LifecycleState != before.LifecycleState {
			t.Fatal("consumed proof reuse changed lifecycle state/epoch")
		}
	}
	rejectReuse(organization.Archive, archiveProof)
	// A fresh proof still succeeds in exactly the authority/state where reuse
	// failed, preventing stale scope or policy denial from becoming the oracle.
	freshProof := issue(organization.Archive)
	freshArchive := prepare(organization.Archive, freshProof)
	commitRole(t, f.orgFixture, freshArchive, nil)
	assertLifecycleProofConsumed(t, f.ctx, f.pool, freshProof, freshArchive, organization.Archive)
	rejectReuse(organization.Restore, restoreProof)
}

func TestOrganizationLifecycleRollbackUnknownAndContention(t *testing.T) {
	f := newOwnerFixture(t, true)
	tenant := transferTenants["org-test-basic"]
	f.create(t, tenant)
	rollbackProof := issueLifecycleProof(t, f.ctx, f.proofOwner, f.auth(tenant, "owner"), identity.UserID(transferUser("owner")), 1, organization.Archive)
	rollbackRequest := organization.LifecycleRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 1, Reason: "maintenance", CorrelationID: "rollback-lifecycle", Proof: rollbackProof}
	p, e := f.service.PrepareArchive(f.ctx, rollbackRequest, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.fail_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled lifecycle rollback'; END $$; CREATE TRIGGER fail_lifecycle BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION organization.fail_lifecycle()`)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("lifecycle escaped outbox rollback", e)
	}
	if v := lifecycleSnapshot(t, f, tenant); v.LifecycleState != organization.LifecycleActive || v.Organization.Version != 1 {
		t.Fatal("rollback leaked lifecycle state")
	}
	_, e = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fail_lifecycle ON public.identity_outbox_bindings; DROP FUNCTION organization.fail_lifecycle()`)
	if e != nil {
		t.Fatal(e)
	}
	// The existing journal keeps the original command's known failed outcome.
	// A new explicitly admitted command may use the unconsumed proof; the failed
	// command itself must not be rewritten or silently retried as another effect.
	rollbackRequest.CommandID = commandID(t)
	p, e = f.service.PrepareArchive(f.ctx, rollbackRequest, "127.0.0.1")
	commitRole(t, f.orgFixture, p, e)
	commitRole(t, f.orgFixture, lifecycleCommand(t, f, tenant, organization.Restore), nil)
	lossy, fault := f.lostCommitService(t)
	v := lifecycleSnapshot(t, f, tenant)
	r := organization.LifecycleRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: v.Organization.Version, Reason: "maintenance", CorrelationID: "lost-lifecycle", Proof: issueLifecycleProof(t, f.ctx, f.proofOwner, f.auth(tenant, "owner"), identity.UserID(transferUser("owner")), 1, organization.Archive)}
	p, e = lossy.PrepareArchive(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	fault.armed.Store(true)
	if got, e := lossy.Execute(f.ctx, p); e == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("lost lifecycle COMMIT claimed outcome", e)
	}
	for range 2 {
		got, e := f.service.Recover(f.ctx, r.Authentication, mustRoleRecovery(t, p))
		if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original lifecycle recovery", e)
		}
	}
	if after := lifecycleSnapshot(t, f, tenant); after.Organization.Version != v.Organization.Version+1 || after.LifecycleState != organization.LifecycleArchived {
		t.Fatal("recovery repeated lifecycle effects")
	}
	a := lifecycleCommand(t, f, tenant, organization.Restore)
	b := lifecycleCommand(t, f, tenant, organization.Restore)
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for _, p := range []organizationpg.PreparedCommand{a, b} {
		wg.Add(1)
		go func(p organizationpg.PreparedCommand) {
			defer wg.Done()
			got, e := f.service.Execute(f.ctx, p)
			results <- e == nil && got.Receipt.Outcome == identity.CommitOutcomeCommitted
		}(p)
	}
	wg.Wait()
	close(results)
	count := 0
	for ok := range results {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatal("concurrent restoration committed twice", count)
	}
}

func TestOrganizationLifecycleTerminalReplayRequiresCurrentOwner(t *testing.T) {
	for _, withdrawal := range []string{"session", "member", "role"} {
		t.Run(withdrawal, func(t *testing.T) {
			f := newOwnerFixture(t, true)
			tenant := transferTenants["org-test-basic"]
			f.create(t, tenant)
			p := lifecycleCommand(t, f, tenant, organization.Archive)
			commitRole(t, f.orgFixture, p, nil)
			var statement string
			switch withdrawal {
			case "session":
				statement = `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`
			case "member":
				statement = `UPDATE organization.memberships SET state='removed' WHERE tenant_id=$1 AND user_id=$2`
			case "role":
				statement = `UPDATE organization.memberships SET role='member' WHERE tenant_id=$1 AND user_id=$2`
			}
			if _, e := f.pool.Raw().Exec(f.ctx, statement, tenant, transferUser("owner")); e != nil {
				t.Fatal(e)
			}
			// The configured external policy still allows archive. Current native
			// session/owner authority must veto even within original observation.
			if got, e := f.service.Execute(f.ctx, p); !errors.Is(e, organization.ErrForbidden) || got != (organization.StoreResult{}) {
				t.Fatal("withdrawn owner received terminal lifecycle receipt", e)
			}
			if _, e := f.service.Recover(f.ctx, f.auth(tenant, "owner"), mustRoleRecovery(t, p)); !errors.Is(e, organization.ErrForbidden) {
				t.Fatal("withdrawn owner recovered lifecycle history", e)
			}
		})
	}
}

func TestOrganizationLifecycleFinalAuthorityRollback(t *testing.T) {
	for _, withdrawal := range []string{"session", "factor", "state"} {
		t.Run(withdrawal, func(t *testing.T) {
			f := newOwnerFixture(t, true)
			tenant := transferTenants["org-test-basic"]
			f.create(t, tenant)
			p := lifecycleCommand(t, f, tenant, organization.Archive)
			body := `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=NEW.tenant_id AND user_id='` + transferUser("owner") + `';`
			if withdrawal == "factor" {
				body = `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=NEW.tenant_id AND user_id='` + transferUser("owner") + `';`
			}
			if withdrawal == "state" {
				body = `UPDATE organization.organizations SET state='active' WHERE tenant_id=NEW.tenant_id AND organization_id=NEW.organization_id;`
			}
			_, e := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.withdraw_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+body+` RETURN NEW; END $$; CREATE TRIGGER withdraw_lifecycle AFTER UPDATE OF lifecycle_changed_at ON organization.organizations FOR EACH ROW EXECUTE FUNCTION organization.withdraw_lifecycle()`)
			if e != nil {
				t.Fatal(e)
			}
			if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("same-Work authority withdrawal committed lifecycle", e)
			}
			if v := lifecycleSnapshot(t, f, tenant); v.Organization.Version != 1 || v.LifecycleState != organization.LifecycleActive {
				t.Fatal("final fence leaked policy/state")
			}
		})
	}
}

func TestOrganizationLifecycleFreshActionTenantAndVersionFences(t *testing.T) {
	f := newOwnerFixture(t, true)
	tenant := transferTenants["org-test-basic"]
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	proof := issueLifecycleProof(t, f.ctx, f.proofOwner, f.auth(tenant, "owner"), identity.UserID(transferUser("owner")), 1, organization.Archive)
	r := organization.LifecycleRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 1, Reason: "maintenance", CorrelationID: "lifecycle", Proof: proof}
	if _, e := f.service.PrepareArchive(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("stale native lifecycle version accepted", e)
	}
	r.OrganizationVersion = 2
	r.Authentication = f.auth(transferTenants["org-test-scope"], "owner")
	if _, e := f.service.PrepareArchive(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("cross-tenant lifecycle proof admitted", e)
	}
	r.Authentication = f.auth(tenant, "member")
	r.Proof = issueLifecycleProof(t, f.ctx, f.proofOwner, r.Authentication, identity.UserID(transferUser("member")), 1, organization.Archive)
	if _, e := f.service.PrepareArchive(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("genuine nonowner proof granted lifecycle", e)
	}
	r.Authentication = f.auth(tenant, "owner")
	r.Proof = proof
	p, e := f.service.PrepareArchive(f.ctx, r, "127.0.0.1")
	commitRole(t, f.orgFixture, p, e)
	r.CommandID = commandID(t)
	r.OrganizationVersion = lifecycleSnapshot(t, f, tenant).Organization.Version
	// A fresh unconsumed archive proof isolates action provenance from replay:
	// changing visible fields cannot turn its authentic signed record into restore.
	r.Proof = issueLifecycleProof(t, f.ctx, f.proofOwner, f.auth(tenant, "owner"), identity.UserID(transferUser("owner")), 1, organization.Archive)
	r.Proof.Action = string(organization.Restore)
	if _, e := f.service.PrepareRestore(f.ctx, r, "127.0.0.1"); e == nil {
		t.Fatal("visible archive proof fields forged restore provenance", e)
	}
}
