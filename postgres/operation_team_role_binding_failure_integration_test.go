//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestTeamRoleBindingOperationMappingAndCommitLoss(t *testing.T) {
	for _, mode := range []string{"assign mapping", "assign commit", "revoke commit"} {
		t.Run(mode, func(t *testing.T) {
			f, r := teamRoleBindingOperationFixture(t, true)
			plain := slugNativeOperationService(t, f.service)
			if mode == "revoke commit" {
				if _, err := plain.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			source, fault := f.lostCommitService(t)
			fault.count.Store(-1)
			mapping := mode == "assign mapping"
			if mapping {
				fault.count.Store(1)
			}
			if mode == "revoke commit" {
				fault.count.Store(0)
			}
			fault.armed.Store(true)
			invoke := func(s *organizationpg.OperationService) (organization.StoreResult, error) {
				if mode == "revoke commit" {
					return s.RevokeTeamDynamicRole(f.ctx, revokeTeamRoleBindingOperationRequest(r), "127.0.0.1")
				}
				return s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1")
			}
			unknown, err := invoke(slugNativeOperationService(t, source))
			if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" {
				t.Fatal("actual lost COMMIT discarded team-role binding original", err)
			}
			for range 2 {
				out, err := invoke(plain)
				if out.Receipt.Binding != unknown.Receipt.Binding {
					t.Fatal("unknown retry allocated new binding command")
				}
				var ambiguity identity.UnknownCommitError
				if mapping {
					if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("mapping-only assignment invented execution", err)
					}
				} else if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("lost committed binding outcome not recovered", err)
				}
			}
			out, err := plain.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: unknown.Receipt.Binding})
			if mapping {
				var ambiguity identity.UnknownCommitError
				if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("explicit mapping-only recovery invented result", err)
				}
				raw, err := base64.RawURLEncoding.DecodeString(string(unknown.Receipt.Binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				var journals, claims, effects int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM organization.command_effects WHERE command_id=$2)`, raw, string(unknown.Receipt.Binding.CommandID)).Scan(&journals, &claims, &effects); err != nil || journals != 0 || claims != 0 || effects != 0 {
					t.Fatal("mapping ambiguity reached binding execution", err)
				}
			} else if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Binding != unknown.Receipt.Binding {
				t.Fatal("explicit original binding recovery differs", err)
			}
		})
	}
}

func TestTeamRoleBindingOperationRequiredEffectsRollback(t *testing.T) {
	for _, op := range []organization.Operation{organization.AssignDynamicRole, organization.RevokeDynamicRole} {
		for _, boundary := range []string{"audit", "outbox"} {
			t.Run(string(op)+"/"+boundary, func(t *testing.T) {
				f, r := teamRoleBindingOperationFixture(t, true)
				s := slugNativeOperationService(t, f.service)
				beforeEpoch, beforeVersion := 5, 0
				if op == organization.RevokeDynamicRole {
					if _, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
						t.Fatal(err)
					}
					beforeEpoch, beforeVersion = 6, 1
				}
				table, condition := "audit.records", "NEW.action='"+string(op)+"' AND NEW.outcome=1"
				if boundary == "outbox" {
					table = "public.identity_outbox_bindings"
					condition = "true"
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.fail_direct_binding() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION 'controlled team-role binding failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_direct_binding BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.fail_direct_binding()`); err != nil {
					t.Fatal(err)
				}
				var out organization.StoreResult
				var failure error
				if op == organization.AssignDynamicRole {
					out, failure = s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1")
				} else {
					out, failure = s.RevokeTeamDynamicRole(f.ctx, revokeTeamRoleBindingOperationRequest(r), "127.0.0.1")
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fail_direct_binding ON `+table+`;DROP FUNCTION organization.fail_direct_binding()`); err != nil {
					t.Fatal(err)
				}
				if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("required effect failure committed binding mutation", failure)
				}
				var epoch, teamEpoch, version, effects int
				var active bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::integer,(SELECT version::integer FROM organization.teams),coalesce((SELECT version::integer FROM organization.team_role_bindings),0),EXISTS(SELECT 1 FROM organization.team_role_bindings WHERE state='active'),(SELECT count(*) FROM organization.command_effects WHERE operation=$1) FROM organization.organizations`, string(op)).Scan(&epoch, &teamEpoch, &version, &active, &effects); err != nil || epoch != beforeEpoch || teamEpoch != int(r.TeamVersion)+beforeVersion || version != beforeVersion || active != (op == organization.RevokeDynamicRole) || effects != 0 {
					t.Fatal("rollback leaked binding epoch/state/original selectors", err)
				}
			})
		}
	}
}

func TestTeamRoleBindingOperationInitialContention(t *testing.T) {
	for _, op := range []organization.Operation{organization.AssignDynamicRole, organization.RevokeDynamicRole} {
		t.Run(string(op), func(t *testing.T) {
			f, r := teamRoleBindingOperationFixture(t, true)
			s := slugNativeOperationService(t, f.service)
			beforeEpoch, beforeVersion := 5, 0
			if op == organization.RevokeDynamicRole {
				if _, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
				beforeEpoch, beforeVersion = 6, 1
				var mu sync.Mutex
				calls := make(map[string]int)
				arrived := 0
				release := make(chan struct{})
				policy := new(directRoleBindingPolicy)
				policy.before = func(ctx context.Context, c authorization.DecisionContext) error {
					if c.Request.Action != authorization.Action(op) || c.Request.Resource.Type != "organization" {
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
					if op == organization.AssignDynamicRole {
						out, err = s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1")
					} else {
						x := revokeTeamRoleBindingOperationRequest(r)
						x.CorrelationID = "initial-team-revoke-" + strconv.Itoa(i)
						out, err = s.RevokeTeamDynamicRole(f.ctx, x, "127.0.0.1")
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
					t.Fatal("initial binding contender had no original result")
				}
				if got.out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					if got.err != nil {
						t.Fatal("committed contender also errored", got.err)
					}
					if winner.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(winner, got.out) {
						t.Fatal("initial contenders disclosed different originals")
					}
					winner = got.out
				}
			}
			if winner.Receipt.Binding.CommandID == "" {
				t.Fatal("no initial binding contender committed")
			}
			var epoch, teamEpoch, version, effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT version::integer FROM organization.organizations),(SELECT version::integer FROM organization.teams),(SELECT version::integer FROM organization.team_role_bindings),(SELECT count(*) FROM organization.command_effects WHERE operation=$1)`, string(op)).Scan(&epoch, &teamEpoch, &version, &effects); err != nil || epoch != beforeEpoch+1 || teamEpoch != int(r.TeamVersion)+beforeVersion+1 || version != beforeVersion+1 || effects != 1 {
				t.Fatal("initial binding contention duplicated effects before any repair", err)
			}
		})
	}
}
