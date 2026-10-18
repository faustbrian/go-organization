//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
)

func nativeTransfer(t *testing.T, f *ownerFixture, tenant, actor, target string, org, source, member uint64) organization.OwnerTransferRequest {
	t.Helper()
	return organization.OwnerTransferRequest{Authentication: f.auth(tenant, actor), CommandID: commandID(t), OrganizationID: metadataOrganization, TargetUserID: identity.UserID(transferUser(target)), OrganizationVersion: org, SourceVersion: source, TargetVersion: member, CorrelationID: "transfer", Proof: issueTransferProof(t, f.ctx, f.proofOwner, f.auth(tenant, actor), identity.UserID(transferUser(actor)), 1, transferFixturePassword)}
}

// RequireEmailRemovalSubjects locks both users FOR UPDATE ORDER BY user_id.
// Hold its first real row while transfer reaches that same boundary, then try
// its second row NOWAIT: a transfer holding the later user would form ABBA with
// the administrative owner. This is a PostgreSQL lock-state oracle, not mocked
// calls or an assertion about query text. The reverse transfer is retained too.
func TestOwnerTransferCanonicalSubjectLockOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "actor-before-target"
		if reverse {
			name = "target-before-actor"
		}
		t.Run(name, func(t *testing.T) {
			f := newOwnerFixture(t)
			tenant := transferTenants["org-test-basic"]
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			actor, target, epoch, version := "owner", "member", uint64(2), uint64(1)
			if reverse {
				first, err := f.service.PrepareOwnerTransfer(f.ctx, nativeTransfer(t, f, tenant, actor, target, epoch, version, version), "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				committedTeam(t, f.orgFixture, first)
				actor, target, epoch, version = "member", "owner", 3, 2
			}
			prepared, err := f.service.PrepareOwnerTransfer(f.ctx, nativeTransfer(t, f, tenant, actor, target, epoch, version, version), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			config, err := pgx.ParseConfig(f.dsn)
			if err != nil {
				t.Fatal(err)
			}
			config.Database = f.database
			admin, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer admin.Close(context.Background())
			var adminPID int32
			if err = admin.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&adminPID); err != nil {
				t.Fatal(err)
			}
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			var first string
			if err = tx.QueryRow(ctx, `SELECT user_id FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, tenant, transferUser("owner")).Scan(&first); err != nil {
				t.Fatal(err)
			}
			type execution struct {
				result organization.StoreResult
				err    error
			}
			finished := make(chan execution, 1)
			go func() { result, err := f.service.Execute(ctx, prepared); finished <- execution{result, err} }()
			joined := false
			defer func() {
				_ = tx.Rollback(context.Background())
				cancel()
				if !joined {
					deadline := time.NewTimer(5 * time.Second)
					defer deadline.Stop()
					select {
					case <-finished:
					case <-deadline.C:
						t.Error("blocked transfer did not terminate after cancellation")
					}
				}
			}()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				var blocked bool
				if err = f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))`, f.database, adminPID).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case got := <-finished:
					joined = true
					t.Fatal("transfer did not wait for administrative user lock", got.err)
				case <-ctx.Done():
					t.Fatal("transfer never reached real subject lock boundary", ctx.Err())
				case <-tick.C:
				}
			}
			rows, err := tx.Query(ctx, `SELECT user_id FROM identity.users WHERE tenant_id=$1 AND user_id IN($2,$3) ORDER BY user_id FOR UPDATE NOWAIT`, tenant, transferUser("owner"), transferUser("member"))
			if err != nil {
				t.Fatal("transfer retained later user ahead of canonical first user", err)
			}
			count := 0
			for rows.Next() {
				count++
			}
			err = rows.Err()
			rows.Close()
			if err != nil || count != 2 {
				t.Fatal("cross-owner canonical lock order would deadlock", err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-finished:
				joined = true
				if got.err != nil || got.result.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("ordered cross-owner transfer did not finish", got.err)
				}
			case <-ctx.Done():
				t.Fatal("ordered cross-owner transfer remained blocked", ctx.Err())
			}
			view, err := f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, actor), OrganizationID: metadataOrganization, CorrelationID: "ordered-transfer"})
			if err != nil || view.Organization.Version != epoch+1 || view.Actor.Role != organization.RoleMember || view.Actor.Version != version+1 {
				t.Fatal("ordered transfer lost atomic role/epoch disposition", err)
			}
		})
	}
}

// Factor activation need not revoke a previously issued SFA session. The
// selected SFA transfer must fence both subjects' current known-empty MFA rows,
// not treat that still-current session or password proof as factor authority.
func TestOwnerTransferFactorAuthority(t *testing.T) {
	for _, subject := range []string{"owner", "member"} {
		for _, stage := range []string{"prepare", "apply", "final"} {
			for _, change := range []string{"activation", "empty-generation"} {
				t.Run(subject+"/"+stage+"/"+change, func(t *testing.T) {
					f := newOwnerFixture(t)
					tenant := transferTenants["org-test-basic"]
					user := transferUser(subject)
					f.create(t, tenant)
					f.add(t, tenant, "member", organization.RoleMember, 1)
					r := nativeTransfer(t, f, tenant, "owner", "member", 2, 1, 1)
					active := 0
					if change == "activation" {
						active = 1
					}
					withdraw := func() {
						t.Helper()
						if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=$3 WHERE tenant_id=$1 AND user_id=$2`, tenant, user, active); err != nil {
							t.Fatal(err)
						}
						version, enrolled, err := mfapg.ReadPasswordSigninFactors(f.ctx, f.pool, identity.TenantID(tenant), identity.UserID(user), time.Second)
						if err != nil || version != 2 || enrolled != (active == 1) {
							t.Fatal("real MFA authority transition", err)
						}
					}
					if stage == "prepare" {
						withdraw()
						_, err := f.service.PrepareOwnerTransfer(f.ctx, r, "127.0.0.1")
						// A new empty generation is safe when preparation observes it;
						// activation is not. The protected cases retain the old epoch.
						if active == 0 {
							if err != nil {
								t.Fatal(err)
							}
							return
						}
						if !errors.Is(err, organization.ErrForbidden) {
							t.Fatal("prepared transfer after factor activation", err)
						}
					} else {
						p, err := f.service.PrepareOwnerTransfer(f.ctx, r, "127.0.0.1")
						if err != nil {
							t.Fatal(err)
						}
						if stage == "apply" {
							withdraw()
						} else {
							// This same-Work oracle proves final revalidation independently
							// of the Apply guard, without revoking/faking any session.
							_, err = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.withdraw_transfer_factor() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=`+strconv.Itoa(active)+` WHERE tenant_id=NEW.tenant_id AND user_id='`+user+`'; RETURN NEW; END $$; CREATE TRIGGER withdraw_transfer_factor AFTER UPDATE ON organization.organizations FOR EACH ROW EXECUTE FUNCTION organization.withdraw_transfer_factor()`)
							if err != nil {
								t.Fatal(err)
							}
						}
						got, err := f.service.Execute(f.ctx, p)
						if !errors.Is(err, organization.ErrForbidden) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
							t.Fatal("transferred ownership after factor authority withdrawal", err)
						}
					}
					assertTransferred(t, f, tenant, 2, 1)
					if _, err := f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, CorrelationID: "factor-current-session"}); err != nil {
						t.Fatal("factor oracle revoked the original session", err)
					}
					var unused bool
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT consumed_command_id IS NULL FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(r.Proof.Proof.ID)).Scan(&unused); err != nil || !unused {
						t.Fatal("factor denial consumed proof", err)
					}
					var effects int
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.owner-transfer'`, tenant).Scan(&effects); err != nil || effects != 0 {
						t.Fatal("factor denial retained transfer effect", err)
					}
				})
			}
		}
	}
}

func TestOwnerTransferRecoveryRevalidatesCallbacks(t *testing.T) {
	for _, stage := range []string{"get", "management", "query"} {
		for _, withdrawal := range []string{"session", "member", "epoch"} {
			t.Run(stage+"/"+withdrawal, func(t *testing.T) {
				f := newOwnerFixture(t)
				tenant := transferTenants["org-test-basic"]
				f.create(t, tenant)
				f.add(t, tenant, "second", organization.RoleOwner, 1)
				f.add(t, tenant, "member", organization.RoleMember, 2)
				p, err := f.service.PrepareOwnerTransfer(f.ctx, nativeTransfer(t, f, tenant, "second", "member", 3, 1, 1), "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				committedTeam(t, f.orgFixture, p)
				handle, err := p.Recovery()
				if err != nil {
					t.Fatal(err)
				}
				policy := &recoveryWithdrawalPolicy{fixture: f.orgFixture, operation: organization.OwnerTransfer, stage: stage, withdrawal: withdrawal, armed: true, tenant: tenant, user: transferUser("second")}
				c := f.configuration
				c.Authorization = policy
				c.Coordinator, err = kernel.NewCoordinator(f.pool, c.Registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x45}}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 1}})
				if err != nil {
					t.Fatal(err)
				}
				s, err := organizationpg.NewService(f.participant, c)
				if err != nil {
					t.Fatal(err)
				}
				got, err := s.Recover(f.ctx, f.auth(tenant, "second"), handle)
				if !policy.fired || !errors.Is(err, organization.ErrForbidden) || got != (organization.StoreResult{}) {
					t.Fatal("transfer outcome disclosed after authority withdrawal", err)
				}
			})
		}
	}
}

// A primary observer can remain current after the session's original freshness
// ceiling. The operation must not turn that observation into reauthentication.
func TestOwnerTransferDeniesStaleAuthentication(t *testing.T) {
	f := newOwnerFixture(t)
	tenant := transferTenants["org-test-basic"]
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	r := nativeTransfer(t, f, tenant, "owner", "member", 2, 1, 1)
	// Preserve the original interval while aging authentication. Render UTC
	// explicitly: the isolated server may use a non-UTC deployment timezone.
	_, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET record=jsonb_set(jsonb_set(record,'{Authentication,Proof,IssuedAt}',to_jsonb(to_char(((record#>>'{Authentication,Proof,IssuedAt}')::timestamptz-interval '16 minutes') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),'{Authentication,Proof,ExpiresAt}',to_jsonb(to_char(((record#>>'{Authentication,Proof,ExpiresAt}')::timestamptz-interval '16 minutes') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))) WHERE tenant_id=$1 AND user_id='01ARZ3NDEKTSV4RRFFQ69G5FB1'`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Get(context.Background(), organization.ReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, CorrelationID: "stale-auth"}); err != nil {
		t.Fatal("stale fixture lost valid read session", err)
	}
	if _, err = f.service.PrepareOwnerTransfer(f.ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("stale authentication transferred owner", err)
	}
}

func assertTransferred(t *testing.T, f *ownerFixture, tenant string, epoch, version int) {
	t.Helper()
	var org, owners, members, source, target, sourceAuthority, targetAuthority int
	var sourceRole, targetRole string
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT o.version::integer,o.owner_count,o.member_count,a.role,a.version::integer,a.authorization_version::integer,b.role,b.version::integer,b.authorization_version::integer FROM organization.organizations o JOIN organization.memberships a USING(tenant_id,organization_id) JOIN organization.memberships b USING(tenant_id,organization_id) WHERE o.tenant_id=$1 AND a.user_id='01ARZ3NDEKTSV4RRFFQ69G5FB1' AND b.user_id='01ARZ3NDEKTSV4RRFFQ69G5FB3'`, tenant).Scan(&org, &owners, &members, &sourceRole, &source, &sourceAuthority, &targetRole, &target, &targetAuthority)
	if err != nil || org != epoch || owners != 1 || members != 2 || source != version || target != version || sourceAuthority != version || targetAuthority != version {
		t.Fatal("transfer epoch/count/membership not atomic", err)
	}
	if version == 2 && (sourceRole != "member" || targetRole != "owner") || version == 1 && (sourceRole != "owner" || targetRole != "member") {
		t.Fatal("wrong ownership disposition")
	}
}

func TestNativeOwnerTransfer(t *testing.T) {
	f := newOwnerFixture(t)
	tenant := transferTenants["org-test-basic"]
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	r := nativeTransfer(t, f, tenant, "owner", "member", 2, 1, 1)
	p, err := f.service.PrepareOwnerTransfer(f.ctx, r, "127.0.0.1")
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
	var retained organizationpg.Recovery
	if err = json.Unmarshal(wire, &retained); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := f.service.Execute(f.ctx, p)
		if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.BeforeVersion != 2 || got.Receipt.Feature.AfterVersion != 3 {
			t.Fatal("transfer/replay", err)
		}
	}
	assertTransferred(t, f, tenant, 3, 2)
	var consumed bool
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT consumed_command_id IS NOT NULL AND consumed_purpose='identity.organization.owner-transfer' FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(r.Proof.Proof.ID)).Scan(&consumed); err != nil || !consumed {
		t.Fatal("transfer did not consume original native primary proof", err)
	}
	// The original actor is now an ordinary member. Receipt disclosure must not
	// become a new owner grant or require undoing the successful demotion.
	for range 2 {
		got, err := f.service.Recover(f.ctx, f.auth(tenant, "owner"), retained)
		if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
			t.Fatal("former-owner exact recovery", err)
		}
	}
	if _, err = f.service.PrepareOwnerTransfer(f.ctx, nativeTransfer(t, f, tenant, "owner", "member", 3, 2, 2), "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("former owner retained transfer authority", err)
	}
	remove, err := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "member"), CommandID: commandID(t), OrganizationID: metadataOrganization, UserID: identity.UserID(transferUser("member")), OrganizationVersion: 3, MemberVersion: 2, CorrelationID: "last-owner"}, "127.0.0.1")
	if !errors.Is(err, organization.ErrLastOwner) || remove != (organizationpg.PreparedCommand{}) {
		t.Fatal("transfer lost last owner", err)
	}
	var effects, events, audits int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.owner-transfer'),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND m.topic='organization.ownership_transferred.v1'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND r.action='identity.organization.transfer_ownership')`, tenant).Scan(&effects, &events, &audits)
	if err != nil || effects != 1 || events != 1 || audits != 1 {
		t.Fatal("transfer audit/outbox missing or duplicated", err)
	}
}

func TestOwnerTransferContentionAndDenial(t *testing.T) {
	for _, competing := range []string{"transfer", "remove"} {
		t.Run(competing, func(t *testing.T) {
			f := newOwnerFixture(t)
			tenant := transferTenants["org-test-race"]
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			first, err := f.service.PrepareOwnerTransfer(f.ctx, nativeTransfer(t, f, tenant, "owner", "member", 2, 1, 1), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			var second organizationpg.PreparedCommand
			if competing == "transfer" {
				second, err = f.service.PrepareOwnerTransfer(f.ctx, nativeTransfer(t, f, tenant, "owner", "member", 2, 1, 1), "127.0.0.1")
			} else {
				second, err = f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, UserID: identity.UserID(transferUser("member")), OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "remove"}, "127.0.0.1")
			}
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			results := make(chan identity.CommitOutcome, 2)
			for _, p := range []organizationpg.PreparedCommand{first, second} {
				wg.Add(1)
				go func(p organizationpg.PreparedCommand) {
					defer wg.Done()
					got, err := f.service.Execute(f.ctx, p)
					if got.Receipt.Outcome == identity.CommitOutcomeCommitted && err == nil {
						results <- got.Receipt.Outcome
					} else if got.Receipt.Outcome == identity.CommitOutcomeNotCommitted && err != nil {
						results <- got.Receipt.Outcome
					} else {
						t.Error("unexpected contended outcome", err)
						results <- identity.CommitOutcomeInvalid
					}
				}(p)
			}
			wg.Wait()
			close(results)
			committed, aborted := 0, 0
			for o := range results {
				if o == identity.CommitOutcomeCommitted {
					committed++
				}
				if o == identity.CommitOutcomeNotCommitted {
					aborted++
				}
			}
			if committed != 1 || aborted != 1 {
				t.Fatal("contention did not serialize")
			}
			var owners, epoch int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT owner_count,version::integer FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&owners, &epoch); err != nil || owners != 1 || epoch != 3 {
				t.Fatal("contention lost owner/epoch", err)
			}
		})
	}
}

func TestOwnerTransferProofCannotBeReusedAfterAuthorityReturns(t *testing.T) {
	f := newOwnerFixture(t)
	tenant := transferTenants["org-test-basic"]
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	original := nativeTransfer(t, f, tenant, "owner", "member", 2, 1, 1)
	p, err := f.service.PrepareOwnerTransfer(f.ctx, original, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f.orgFixture, p)
	back := nativeTransfer(t, f, tenant, "member", "owner", 3, 2, 2)
	p, err = f.service.PrepareOwnerTransfer(f.ctx, back, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f.orgFixture, p)
	// Current source/target roles and all expected versions are valid again;
	// only the original one-use proof's consumed marker must deny this attempt.
	original.CommandID = commandID(t)
	original.OrganizationVersion = 4
	original.SourceVersion = 3
	original.TargetVersion = 3
	p, err = f.service.PrepareOwnerTransfer(f.ctx, original, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.service.Execute(f.ctx, p)
	if !errors.Is(err, organization.ErrForbidden) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("consumed proof transferred ownership again", err)
	}
	var epoch int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT version::integer FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&epoch); err != nil || epoch != 4 {
		t.Fatal("proof replay advanced policy epoch", err)
	}
}

func TestOwnerTransferRollbackAndLostAcknowledgement(t *testing.T) {
	for _, table := range []string{"public.identity_outbox_bindings", "audit.records"} {
		t.Run(table, func(t *testing.T) {
			f := newOwnerFixture(t)
			tenant := transferTenants["org-test-rollback"]
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			r := nativeTransfer(t, f, tenant, "owner", "member", 2, 1, 1)
			p, err := f.service.PrepareOwnerTransfer(f.ctx, r, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			// Leave the coordinator's separate aborted-result audit writable;
			// fail only this protected success publication, not all journaling.
			body := `RAISE EXCEPTION 'controlled transfer rollback';`
			if table == "audit.records" {
				body = `IF NEW.outcome=1 AND NEW.action='identity.organization.transfer_ownership' THEN RAISE EXCEPTION 'controlled transfer rollback'; END IF; RETURN NEW;`
			}
			_, err = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.reject_owner_transfer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+body+` END $$; CREATE TRIGGER reject_owner_transfer BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION public.reject_owner_transfer()`)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.service.Execute(f.ctx, p)
			if err == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("failed publication retained ownership", err)
			}
			assertTransferred(t, f, tenant, 2, 1)
			var unused bool
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT consumed_command_id IS NULL FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(r.Proof.Proof.ID)).Scan(&unused); err != nil || !unused {
				t.Fatal("rollback consumed the primary proof", err)
			}
			_, err = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_owner_transfer ON `+table+`; DROP FUNCTION public.reject_owner_transfer()`)
			if err != nil {
				t.Fatal(err)
			}
			lossy, fault := f.lostCommitService(t)
			p, err = lossy.PrepareOwnerTransfer(f.ctx, nativeTransfer(t, f, tenant, "owner", "member", 2, 1, 1), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			handle, err := p.Recovery()
			if err != nil {
				t.Fatal(err)
			}
			fault.armed.Store(true)
			got, err = lossy.Execute(f.ctx, p)
			if err == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("lost transfer commit claimed outcome", err)
			}
			for range 2 {
				got, err = f.service.Recover(f.ctx, f.auth(tenant, "owner"), handle)
				if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
					t.Fatal("lost transfer reconciliation", err)
				}
			}
			assertTransferred(t, f, tenant, 3, 2)
		})
	}
}

func TestOwnerTransferScopeAndCurrentAuthority(t *testing.T) {
	for _, variant := range []string{"admin", "member", "outsider", "outsider-target", "self", "foreign-tenant", "foreign-org", "stale-org", "stale-source", "stale-target", "late-session", "late-target", "late-source", "late-policy"} {
		t.Run(variant, func(t *testing.T) {
			f := newOwnerFixture(t)
			tenant := transferTenants["org-test-scope"]
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			f.add(t, tenant, "second", organization.RoleAdministrator, 2)
			actor := "owner"
			switch variant {
			case "admin":
				actor = "second"
			case "member", "outsider":
				actor = variant
			}
			// Nonowners present their own authentic primary proof. Their denial
			// must establish role enforcement, not merely a proof/actor mismatch.
			r := nativeTransfer(t, f, tenant, actor, "member", 3, 1, 1)
			want := organization.ErrForbidden
			switch variant {
			case "member":
				r.TargetUserID = identity.UserID(transferUser("second"))
			case "outsider-target":
				r.TargetUserID = identity.UserID(transferUser("outsider"))
			case "self":
				r.TargetUserID = identity.UserID(transferUser("owner"))
			case "foreign-tenant":
				r.Authentication.TenantID = identity.TenantID(transferTenants["org-test-basic"])
			case "foreign-org":
				r.OrganizationID = "another-org"
			case "stale-org":
				r.OrganizationVersion--
				want = organization.ErrConflict
			case "stale-source":
				r.SourceVersion++
				want = organization.ErrConflict
			case "stale-target":
				r.TargetVersion++
				want = organization.ErrConflict
			}
			p, err := f.service.PrepareOwnerTransfer(f.ctx, r, "127.0.0.1")
			if len(variant) < 5 || variant[:5] != "late-" {
				if !errors.Is(err, want) || p != (organizationpg.PreparedCommand{}) {
					t.Fatal("unsafe transfer prepared", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "late-session":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='01ARZ3NDEKTSV4RRFFQ69G5FB1'`, tenant)
			case "late-target":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id='01ARZ3NDEKTSV4RRFFQ69G5FB3'`, tenant)
			case "late-source":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET role='member',version=version+1 WHERE tenant_id=$1 AND user_id='01ARZ3NDEKTSV4RRFFQ69G5FB1'`, tenant)
			case "late-policy":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id=$1 AND policy_namespace<>'users' AND subject_id='01ARZ3NDEKTSV4RRFFQ69G5FB3'`, tenant)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.service.Execute(f.ctx, p)
			if err == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("withdrawn authority committed transfer", err)
			}
			var epoch, effects int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT version::integer,(SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.owner-transfer') FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&epoch, &effects); err != nil || epoch != 3 || effects != 0 {
				t.Fatal("denial retained transfer effects", err)
			}
		})
	}
}
