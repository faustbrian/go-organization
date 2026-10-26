//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestDynamicRoleOperationMappingAndCommitLoss(t *testing.T) {
	for _, mode := range []string{"create mapping", "create commit", "update mapping", "update commit", "delete commit"} {
		t.Run(mode, func(t *testing.T) {
			f := dynamicRoleOperationFixture(t, true)
			r := createRoleOperationRequest(t, f)
			u := updateRoleOperationRequest(t, r, 3, 1)
			plain := slugNativeOperationService(t, f.service)
			if !strings.HasPrefix(mode, "create") {
				if _, err := plain.CreateDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "delete commit" {
				if _, err := plain.UpdateDynamicRole(f.ctx, u, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			source, fault := f.lostCommitService(t)
			fault.count.Store(-1)
			mapping := strings.HasSuffix(mode, "mapping")
			if mapping {
				fault.count.Store(1)
			}
			if mode == "delete commit" {
				fault.count.Store(0)
			}
			fault.armed.Store(true)
			var unknown organization.StoreResult
			var err error
			s := slugNativeOperationService(t, source)
			invoke := func(s *organizationpg.OperationService) (organization.StoreResult, error) {
				switch {
				case strings.HasPrefix(mode, "create"):
					return s.CreateDynamicRole(f.ctx, r, "127.0.0.1")
				case mode == "delete commit":
					return s.DeleteDynamicRole(f.ctx, deleteRoleOperationRequest(u), "127.0.0.1")
				default:
					return s.UpdateDynamicRole(f.ctx, u, "127.0.0.1")
				}
			}
			unknown, err = invoke(s)
			if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" {
				t.Fatal("actual lost COMMIT discarded original role scope", err)
			}
			for range 2 {
				out, err := invoke(plain)
				if out.Receipt.Binding != unknown.Receipt.Binding {
					t.Fatal("unknown role retry allocated another command")
				}
				var ambiguity identity.UnknownCommitError
				if mapping {
					if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("mapping-only role request invented execution or terminal outcome", err)
					}
				} else if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("lost committed role outcome not recovered", err)
				}
			}
			out, err := plain.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: unknown.Receipt.Binding})
			if mapping {
				var ambiguity identity.UnknownCommitError
				if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("explicit mapping-only role recovery invented a result", err)
				}
				raw, err := base64.RawURLEncoding.DecodeString(string(unknown.Receipt.Binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				var journals, claims, effects int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM organization.command_effects WHERE command_id=$2)`, raw, string(unknown.Receipt.Binding.CommandID)).Scan(&journals, &claims, &effects); err != nil || journals != 0 || claims != 0 || effects != 0 {
					t.Fatal("mapping-only ambiguity reached domain execution", err)
				}
			} else if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Binding != unknown.Receipt.Binding {
				t.Fatal("explicit original role COMMIT recovery differs", err)
			}
		})
	}
}

func TestDynamicRoleOperationRequiredEffectsRollback(t *testing.T) {
	for _, op := range []organization.Operation{organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole} {
		for _, boundary := range []string{"audit", "outbox"} {
			t.Run(string(op)+"/"+boundary, func(t *testing.T) {
				f := dynamicRoleOperationFixture(t, true)
				r := createRoleOperationRequest(t, f)
				u := updateRoleOperationRequest(t, r, 3, 1)
				s := slugNativeOperationService(t, f.service)
				beforeEpoch, beforeVersion := 2, 0
				if op != organization.CreateDynamicRole {
					if _, err := s.CreateDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
						t.Fatal(err)
					}
					beforeEpoch, beforeVersion = 3, 1
				}
				if op == organization.DeleteDynamicRole {
					if _, err := s.UpdateDynamicRole(f.ctx, u, "127.0.0.1"); err != nil {
						t.Fatal(err)
					}
					beforeEpoch, beforeVersion = 4, 2
				}
				table, condition := "audit.records", "NEW.action='"+string(op)+"' AND NEW.outcome=1"
				if boundary == "outbox" {
					table = "public.identity_outbox_bindings"
					condition = "true"
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.fail_role_operation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION 'controlled role operation failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_role_operation BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.fail_role_operation()`); err != nil {
					t.Fatal(err)
				}
				var out organization.StoreResult
				var failure error
				switch op {
				case organization.CreateDynamicRole:
					out, failure = s.CreateDynamicRole(f.ctx, r, "127.0.0.1")
				case organization.UpdateDynamicRole:
					out, failure = s.UpdateDynamicRole(f.ctx, u, "127.0.0.1")
				case organization.DeleteDynamicRole:
					out, failure = s.DeleteDynamicRole(f.ctx, deleteRoleOperationRequest(u), "127.0.0.1")
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fail_role_operation ON `+table+`;DROP FUNCTION organization.fail_role_operation()`); err != nil {
					t.Fatal(err)
				}
				if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("required effect failure committed role mutation", failure)
				}
				var epoch, version, effects int
				var retired bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::integer,coalesce((SELECT version::integer FROM organization.custom_roles),0),EXISTS(SELECT 1 FROM organization.custom_roles WHERE state='deleted'),(SELECT count(*) FROM organization.command_effects WHERE operation=$1) FROM organization.organizations`, string(op)).Scan(&epoch, &version, &retired, &effects); err != nil || epoch != beforeEpoch || version != beforeVersion || retired || effects != 0 {
					t.Fatal("rollback leaked role state, epoch or original correlation", err)
				}
			})
		}
	}
}

func TestDynamicRoleOperationInitialContention(t *testing.T) {
	for _, op := range []organization.Operation{organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole} {
		t.Run(string(op), func(t *testing.T) {
			f := dynamicRoleOperationFixture(t, true)
			r := createRoleOperationRequest(t, f)
			u := updateRoleOperationRequest(t, r, 3, 1)
			s := slugNativeOperationService(t, f.service)
			beforeEpoch := 2
			if op != organization.CreateDynamicRole {
				if _, err := s.CreateDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
				beforeEpoch = 3
			}
			if op == organization.DeleteDynamicRole {
				if _, err := s.UpdateDynamicRole(f.ctx, u, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
				beforeEpoch = 4
				// The second actual management callback follows an empty original
				// lookup. Hold both there so success cannot be supplied by a later
				// sequential repair or a contender that only observed the winner.
				var mu sync.Mutex
				calls := make(map[string]int)
				arrived := 0
				release := make(chan struct{})
				policy := new(dynamicRoleOperationPolicy)
				policy.before = func(ctx context.Context, c authorization.DecisionContext) error {
					if c.Request.Action != authorization.Action(organization.DeleteDynamicRole) || c.Request.Resource.Type != "organization" {
						return nil
					}
					mu.Lock()
					calls[c.CorrelationID]++
					wait := calls[c.CorrelationID] == 2
					if wait {
						arrived++
						if arrived == 2 {
							close(release)
						}
					}
					mu.Unlock()
					if wait {
						select {
						case <-release:
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					return nil
				}
				s = leaveOperationPolicyFacade(t, f, policy, nil)
			}
			start := make(chan struct{})
			type result struct {
				out organization.StoreResult
				err error
			}
			results := make(chan result, 2)
			var wg sync.WaitGroup
			for i := range 2 {
				wg.Go(func() {
					<-start
					var out organization.StoreResult
					var err error
					switch op {
					case organization.CreateDynamicRole:
						out, err = s.CreateDynamicRole(f.ctx, r, "127.0.0.1")
					case organization.UpdateDynamicRole:
						out, err = s.UpdateDynamicRole(f.ctx, u, "127.0.0.1")
					case organization.DeleteDynamicRole:
						x := deleteRoleOperationRequest(u)
						x.CorrelationID = "initial-delete-" + strconv.Itoa(i)
						out, err = s.DeleteDynamicRole(f.ctx, x, "127.0.0.1")
					}
					results <- result{out, err}
				})
			}
			close(start)
			wg.Wait()
			close(results)
			var winner organization.StoreResult
			for got := range results {
				if got.err == nil && got.out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("initial contender returned no original outcome")
				}
				if got.out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					if got.err != nil {
						t.Fatal("committed contender also returned error", got.err)
					}
					if winner.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(winner, got.out) {
						t.Fatal("initial contenders returned different successful originals")
					}
					winner = got.out
				}
			}
			if winner.Receipt.Binding.CommandID == "" {
				t.Fatal("neither initial role contender committed")
			}
			var effects, epoch, version int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE operation=$1),(SELECT version::integer FROM organization.organizations),(SELECT version::integer FROM organization.custom_roles)`, string(op)).Scan(&effects, &epoch, &version); err != nil || effects != 1 || epoch != beforeEpoch+1 || version != beforeEpoch-1 {
				t.Fatal("initial contention duplicated role effects before repair", err)
			}
		})
	}
}
