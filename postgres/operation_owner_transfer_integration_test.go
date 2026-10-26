//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type ownerTransferOperation interface {
	OwnerTransfer(context.Context, organization.OwnerTransferOperationRequest, string) (organization.StoreResult, error)
}

func ownerTransferOperationFixture(t *testing.T) *ownerFixture {
	t.Helper()
	f := newOwnerFixture(t)
	c, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	c.Database = f.database
	db := stdlib.OpenDB(*c)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("owner_transfer_operation")
	if err != nil {
		t.Fatal(err)
	}
	history, err := (kernel.RequestKeyPreparationMigrationSource{Base: kernel.RequestKeyMigrationSource{Base: f.history, Version: 320}, Version: 321}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(history[len(f.history):]), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("existing request-key migration", err)
	}
	return f
}

func keyedTransferRequest(t *testing.T, f *ownerFixture, tenant, actor, target, label string, epoch, source, destination uint64) organization.OwnerTransferOperationRequest {
	t.Helper()
	r := nativeTransfer(t, f, tenant, actor, target, epoch, source, destination)
	key, err := identity.NewIdempotencyKey([]byte("original-transfer-" + label))
	if err != nil {
		t.Fatal(err)
	}
	return organization.OwnerTransferOperationRequest{Authentication: r.Authentication, IdempotencyKey: key, OrganizationID: r.OrganizationID, TargetUserID: r.TargetUserID, OrganizationVersion: r.OrganizationVersion, SourceVersion: r.SourceVersion, TargetVersion: r.TargetVersion, CorrelationID: r.CorrelationID, Proof: r.Proof}
}

func invokeOwnerTransfer(t *testing.T, facade *organizationpg.OperationService, ctx context.Context, r organization.OwnerTransferOperationRequest) (organization.StoreResult, error) {
	t.Helper()
	operation, ok := any(facade).(ownerTransferOperation)
	if !ok {
		t.Fatal("native original-key owner-transfer operation is missing")
	}
	return operation.OwnerTransfer(ctx, r, "127.0.0.1")
}

func TestOwnerTransferOperationOriginalKeyAndReconstruction(t *testing.T) {
	f := ownerTransferOperationFixture(t)
	tenant := transferTenants["org-test-basic"]
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	r := keyedTransferRequest(t, f, tenant, "owner", "member", "original", 2, 1, 1)
	facade := slugNativeOperationService(t, f.service)
	original, err := invokeOwnerTransfer(t, facade, f.ctx, r)
	if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted || original.Receipt.Feature == nil || original.Receipt.Feature.BeforeVersion != 2 || original.Receipt.Feature.AfterVersion != 3 {
		t.Fatal("keyed ownership transfer did not commit", err)
	}
	assertTransferred(t, f, tenant, 3, 2)
	r.CorrelationID = "retry-keeps-original"
	for range 2 {
		got, err := invokeOwnerTransfer(t, slugNativeOperationService(t, f.service), f.ctx, r)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("former-owner retry lost original metadata", err)
		}
	}
	got, err := facade.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding})
	if err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal("explicit original transfer recovery", err)
	}
	for name, change := range map[string]func(*organization.OwnerTransferOperationRequest){
		"target": func(r *organization.OwnerTransferOperationRequest) {
			r.TargetUserID = identity.UserID(transferUser("second"))
		},
		"organization":         func(r *organization.OwnerTransferOperationRequest) { r.OrganizationID = "another-org" },
		"organization version": func(r *organization.OwnerTransferOperationRequest) { r.OrganizationVersion++ },
		"source version":       func(r *organization.OwnerTransferOperationRequest) { r.SourceVersion++ },
		"target version":       func(r *organization.OwnerTransferOperationRequest) { r.TargetVersion++ },
		"proof id":             func(r *organization.OwnerTransferOperationRequest) { r.Proof.Proof.ID += "a" },
		"proof deadline": func(r *organization.OwnerTransferOperationRequest) {
			r.Proof.Proof.ExpiresAt = r.Proof.Proof.ExpiresAt.Add(-1)
		},
		"proof session": func(r *organization.OwnerTransferOperationRequest) { r.Proof.SessionID += "a" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if _, err := invokeOwnerTransfer(t, facade, f.ctx, changed); !errors.Is(err, organization.ErrConflict) {
				t.Fatal("changed original intent did not conflict", err)
			}
		})
	}
	var effects, events, audits int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.owner-transfer'),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND m.topic='organization.ownership_transferred.v1'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND r.action='identity.organization.transfer_ownership')`, tenant).Scan(&effects, &events, &audits)
	if err != nil || effects != 1 || events != 1 || audits != 1 {
		t.Fatal("retry duplicated protected effects", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, tenant, transferUser("owner")); err != nil {
		t.Fatal(err)
	}
	if _, err = invokeOwnerTransfer(t, facade, f.ctx, r); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("revoked original actor recovered transfer", err)
	}
}

func TestOwnerTransferOperationAdmissionDenials(t *testing.T) {
	for _, variant := range []string{"self", "administrator", "outsider-target", "foreign-tenant", "foreign-org", "stale-org", "stale-source", "stale-target", "wrong-proof-session"} {
		t.Run(variant, func(t *testing.T) {
			f := ownerTransferOperationFixture(t)
			tenant := transferTenants["org-test-scope"]
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			f.add(t, tenant, "second", organization.RoleAdministrator, 2)
			actor := "owner"
			if variant == "administrator" {
				actor = "second"
			}
			r := keyedTransferRequest(t, f, tenant, actor, "member", variant, 3, 1, 1)
			want := organization.ErrForbidden
			switch variant {
			case "self":
				r.TargetUserID = identity.UserID(transferUser("owner"))
			case "outsider-target":
				r.TargetUserID = identity.UserID(transferUser("outsider"))
			case "foreign-tenant":
				r.Authentication.TenantID = identity.TenantID(transferTenants["org-test-basic"])
				want = organization.ErrInvalidInput
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
			case "wrong-proof-session":
				r.Proof.SessionID += "a"
			}
			if _, err := invokeOwnerTransfer(t, slugNativeOperationService(t, f.service), f.ctx, r); !errors.Is(err, want) {
				t.Fatal("unsafe keyed transfer admitted", err)
			}
			var effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.owner-transfer'`, tenant).Scan(&effects); err != nil || effects != 0 {
				t.Fatal("denial retained protected effect", err)
			}
		})
	}
}

func TestOwnerTransferOperationConcurrentOriginalKeys(t *testing.T) {
	for _, competing := range []string{"same-key", "another-transfer", "remove"} {
		t.Run(competing, func(t *testing.T) {
			f := ownerTransferOperationFixture(t)
			tenant := transferTenants["org-test-race"]
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			r := keyedTransferRequest(t, f, tenant, "owner", "member", "first", 2, 1, 1)
			facade := slugNativeOperationService(t, f.service)
			second := r
			if competing == "another-transfer" {
				second = keyedTransferRequest(t, f, tenant, "owner", "member", "second", 2, 1, 1)
			}
			var remove organizationpg.PreparedCommand
			var err error
			if competing == "remove" {
				remove, err = f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, UserID: r.TargetUserID, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "competing-remove"}, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
			}
			type result struct {
				out organization.StoreResult
				err error
			}
			results := make(chan result, 2)
			var wg sync.WaitGroup
			wg.Go(func() { out, err := invokeOwnerTransfer(t, facade, f.ctx, r); results <- result{out, err} })
			wg.Go(func() {
				var out organization.StoreResult
				var err error
				if competing == "remove" {
					out, err = f.service.Execute(f.ctx, remove)
				} else {
					out, err = invokeOwnerTransfer(t, facade, f.ctx, second)
				}
				results <- result{out, err}
			})
			wg.Wait()
			close(results)
			commits := 0
			var original organization.StoreResult
			var transient []organization.StoreResult
			for got := range results {
				if got.err == nil && got.out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					commits++
					if competing == "same-key" && original.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(original, got.out) {
						t.Fatal("same key returned different commands")
					}
					original = got.out
				} else if got.err == nil {
					t.Fatal("contention silently lost outcome")
				} else if competing == "same-key" {
					var unknown identity.UnknownCommitError
					if errors.As(got.err, &unknown) && got.out.Receipt.Outcome == identity.CommitOutcomeUnknown && got.out.Receipt.Binding.CommandID == unknown.CommandID {
						transient = append(transient, got.out)
					} else if !errors.Is(got.err, organization.ErrForbidden) || got.out.Receipt.Outcome != identity.CommitOutcomeInvalid {
						t.Fatal("same-key contention invented a definitive outcome", got.err, got.out.Receipt.Outcome)
					}
				}
			}
			if competing == "same-key" {
				if commits < 1 || commits > 2 {
					t.Fatal("same-key contention lost winning original")
				}
				for _, got := range transient {
					if got.Receipt.Binding != original.Receipt.Binding {
						t.Fatal("in-progress contender adopted another original command")
					}
				}
				// Recovery can observe an in-progress journal, or correctly deny a
				// disclosure snapshot changed by the winning transfer. Once both
				// calls finish, the same key must classify that exact committed
				// original, never retry execution or remain permanently denied.
				got, err := invokeOwnerTransfer(t, slugNativeOperationService(t, f.service), f.ctx, r)
				if err != nil || !reflect.DeepEqual(got, original) {
					t.Fatal("stable same-key retry did not recover winning original", err)
				}
			} else if commits != 1 {
				t.Fatal("ownership contention did not serialize", commits)
			}
			var epoch, owners, effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::integer,owner_count,(SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation IN ('identity.organization.owner-transfer','identity.organization.member.remove')) FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&epoch, &owners, &effects); err != nil || epoch != 3 || owners != 1 || effects != 1 {
				t.Fatal("contention lost ownership", err)
			}
		})
	}
}

func TestOwnerTransferOperationRecoveryRevalidatesCurrentAuthority(t *testing.T) {
	for _, stage := range []string{"get", "management", "query"} {
		for _, withdrawal := range []string{"session", "member", "epoch"} {
			t.Run(stage+"/"+withdrawal, func(t *testing.T) {
				f := ownerTransferOperationFixture(t)
				tenant := transferTenants["org-test-basic"]
				f.create(t, tenant)
				f.add(t, tenant, "member", organization.RoleMember, 1)
				r := keyedTransferRequest(t, f, tenant, "owner", "member", "withdrawal", 2, 1, 1)
				original, err := invokeOwnerTransfer(t, slugNativeOperationService(t, f.service), f.ctx, r)
				if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal(err)
				}
				policy := &recoveryWithdrawalPolicy{fixture: f.orgFixture, operation: organization.OwnerTransfer, stage: stage, withdrawal: withdrawal, armed: true, tenant: tenant, user: transferUser("owner")}
				c := f.configuration
				c.Authorization = policy
				source, err := organizationpg.NewService(f.participant, c)
				if err != nil {
					t.Fatal(err)
				}
				query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 1}
				keys, err := kernel.NewRequestKeyConfig("slug-native-read", [32]byte{0x51}, query)
				if err != nil {
					t.Fatal(err)
				}
				custody, err := organizationpg.NewOperationCustodyConfig("slug-native-read", map[string][]byte{"slug-native-read": bytes.Repeat([]byte{0x52}, 32)})
				if err != nil {
					t.Fatal(err)
				}
				facade, err := organizationpg.NewOperationService(source, organizationpg.OperationServiceConfig{ConfigurationID: "slug-native-read", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x53}}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: keys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) {
					t.Error("recovery allocated organization")
					return "", organization.ErrUnavailable
				}})
				if err != nil {
					t.Fatal(err)
				}
				out, err := invokeOwnerTransfer(t, facade, f.ctx, r)
				if !policy.fired || !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome != identity.CommitOutcomeInvalid {
					t.Fatal("withdrawn current authority disclosed original transfer", err)
				}
			})
		}
	}
}

func TestOwnerTransferOperationRollbackAndCommitLoss(t *testing.T) {
	for _, variant := range []string{"rollback", "mapping-only", "lost-domain-commit"} {
		t.Run(variant, func(t *testing.T) {
			f := ownerTransferOperationFixture(t)
			tenant := transferTenants["org-test-rollback"]
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			r := keyedTransferRequest(t, f, tenant, "owner", "member", variant, 2, 1, 1)
			if variant == "rollback" {
				if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.reject_keyed_owner_transfer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled keyed transfer rollback'; END $$; CREATE TRIGGER reject_keyed_owner_transfer BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.reject_keyed_owner_transfer()`); err != nil {
					t.Fatal(err)
				}
				out, err := invokeOwnerTransfer(t, slugNativeOperationService(t, f.service), f.ctx, r)
				if err == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("failed publication retained ownership", err)
				}
				assertTransferred(t, f, tenant, 2, 1)
				var unused bool
				if err = f.pool.Raw().QueryRow(f.ctx, `SELECT consumed_command_id IS NULL FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(r.Proof.Proof.ID)).Scan(&unused); err != nil || !unused {
					t.Fatal("rollback consumed original proof", err)
				}
				if _, err = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_keyed_owner_transfer ON public.identity_outbox_bindings; DROP FUNCTION public.reject_keyed_owner_transfer()`); err != nil {
					t.Fatal(err)
				}
				recovered, err := invokeOwnerTransfer(t, slugNativeOperationService(t, f.service), f.ctx, r)
				if !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(recovered, out) {
					t.Fatal("aborted original was executed again", err)
				}
				assertTransferred(t, f, tenant, 2, 1)
				return
			}
			lossy, fault := f.lostCommitService(t)
			fault.count.Store(-1)
			if variant == "mapping-only" {
				fault.count.Store(1)
			}
			fault.armed.Store(true)
			out, err := invokeOwnerTransfer(t, slugNativeOperationService(t, lossy), f.ctx, r)
			if err == nil || !fault.lost.Load() || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.Receipt.Binding.CommandID == "" {
				t.Fatal("COMMIT loss did not retain original unknown", err, out.Receipt.Outcome)
			}
			raw, err := base64.RawURLEncoding.Strict().DecodeString(string(out.Receipt.Binding.CommandID))
			if err != nil {
				t.Fatal(err)
			}
			var mappings, claims, journals int
			var unused bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.request_key_mappings WHERE command_id=$1 AND route_id='identity.organization.owner-transfer'),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT consumed_command_id IS NULL FROM identity_password.reauthentication_records WHERE proof_id=$2)`, raw, string(r.Proof.Proof.ID)).Scan(&mappings, &claims, &journals, &unused); err != nil {
				t.Fatal(err)
			}
			wantJournal := 1
			if variant == "mapping-only" {
				wantJournal = 0
			}
			if mappings != 1 || claims != wantJournal || journals != wantJournal || unused != (variant == "mapping-only") {
				t.Fatal("fault missed original mapping/journal/proof boundary", mappings, claims, journals, unused)
			}
			t.Log("original mapping/claims/journal and proof-unused", mappings, claims, journals, unused)
			for range 2 {
				got, err := invokeOwnerTransfer(t, slugNativeOperationService(t, f.service), f.ctx, r)
				var unknown identity.UnknownCommitError
				if got.Receipt.Binding != out.Receipt.Binding || variant == "mapping-only" && (!errors.As(err, &unknown) || got.Receipt.Outcome != identity.CommitOutcomeUnknown) || variant != "mapping-only" && (err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted) {
					t.Fatal("original-key recovery replaced unknown command", err)
				}
			}
			if variant == "mapping-only" {
				assertTransferred(t, f, tenant, 2, 1)
			} else {
				assertTransferred(t, f, tenant, 3, 2)
			}
		})
	}
}
