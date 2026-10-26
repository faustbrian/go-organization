//go:build integration

package postgres_test

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestTeamLifecycleOperationMappingAndCommitLoss(t *testing.T) {
	for _, mode := range []string{"mapping", "rename commit", "delete commit"} {
		t.Run(mode, func(t *testing.T) {
			f := teamLifecycleOperationFixture(t, true)
			r := teamLifecycleOperationRequest(t, f)
			plain := slugNativeOperationService(t, f.service)
			if mode == "delete commit" {
				if _, err := plain.UpdateTeam(f.ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			source, fault := f.lostCommitService(t)
			fault.count.Store(-1)
			if mode == "mapping" {
				fault.count.Store(1)
			}
			if mode == "delete commit" {
				fault.count.Store(0)
			}
			fault.armed.Store(true)
			var unknown organization.StoreResult
			var err error
			if mode == "delete commit" {
				unknown, err = slugNativeOperationService(t, source).DeleteTeam(f.ctx, teamDeleteOperationRequest(r), "127.0.0.1")
			} else {
				unknown, err = slugNativeOperationService(t, source).UpdateTeam(f.ctx, r, "127.0.0.1")
			}
			if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" {
				t.Fatal("actual lost COMMIT discarded original scope", err)
			}
			for range 2 {
				var out organization.StoreResult
				if mode == "delete commit" {
					out, err = plain.DeleteTeam(f.ctx, teamDeleteOperationRequest(r), "127.0.0.1")
				} else {
					out, err = plain.UpdateTeam(f.ctx, r, "127.0.0.1")
				}
				if out.Receipt.Binding != unknown.Receipt.Binding {
					t.Fatal("unknown retry allocated different command")
				}
				var ambiguity identity.UnknownCommitError
				if mode == "mapping" {
					if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("mapping-only original invented execution or terminal outcome", err)
					}
				} else if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("lost committed transition not recovered", err)
				}
			}
			if mode == "mapping" {
				raw, err := base64.RawURLEncoding.DecodeString(string(unknown.Receipt.Binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				var claims, journals, renames int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM organization.command_effects WHERE operation='identity.organization.team.update')`, raw).Scan(&journals, &claims, &renames); err != nil || journals != 0 || claims != 0 || renames != 0 {
					t.Fatal("mapping-only ambiguity reached execution", err)
				}
			}
		})
	}
}

func TestTeamLifecycleOperationRequiredEffectsRollback(t *testing.T) {
	for _, mode := range []string{"rename audit", "rename outbox", "delete audit", "delete outbox"} {
		t.Run(mode, func(t *testing.T) {
			f := teamLifecycleOperationFixture(t, true)
			r := teamLifecycleOperationRequest(t, f)
			s := slugNativeOperationService(t, f.service)
			deleting := strings.HasPrefix(mode, "delete")
			action, topic := "identity.organization.update_team", "team.updated.v1"
			if deleting {
				if _, err := s.UpdateTeam(f.ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
				action, topic = "identity.organization.delete_team", "team.deleted.v1"
			}
			table, condition := "audit.records", "NEW.action='"+action+"' AND NEW.outcome=1"
			if strings.HasSuffix(mode, "outbox") {
				table = "outbox_messages"
				condition = "NEW.topic='" + topic + "'"
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.fail_team_lifecycle_operation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION 'controlled team lifecycle failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_team_lifecycle_operation BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.fail_team_lifecycle_operation()`); err != nil {
				t.Fatal(err)
			}
			var out organization.StoreResult
			var failure error
			if deleting {
				out, failure = s.DeleteTeam(f.ctx, teamDeleteOperationRequest(r), "127.0.0.1")
			} else {
				out, failure = s.UpdateTeam(f.ctx, r, "127.0.0.1")
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fail_team_lifecycle_operation ON `+table+`;DROP FUNCTION organization.fail_team_lifecycle_operation()`); err != nil {
				t.Fatal(err)
			}
			if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("required effect failure committed lifecycle mutation", failure)
			}
			var epoch, version, retired, deletions int
			var name string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT o.version::integer,t.version::integer,t.name,coalesce(i.deleted_version,0)::integer,(SELECT count(*) FROM organization.command_effects WHERE operation='identity.organization.team.delete') FROM organization.organizations o JOIN organization.teams t USING(tenant_id,organization_id) JOIN organization.team_identities i USING(tenant_id,organization_id,team_id)`).Scan(&epoch, &version, &name, &retired, &deletions); err != nil || retired != 0 || deletions != 0 || deleting && (epoch != 5 || version != 3 || name != "Platform") || !deleting && (epoch != 4 || version != 2 || name != "engineering") {
				t.Fatal("rollback retained changed name, epoch or terminal identity", err)
			}
			if !deleting {
				if got, err := s.UpdateTeam(f.ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(got, out) {
					t.Fatal("aborted original rename executed again", err)
				}
			}
		})
	}
}

func TestTeamLifecycleOperationInitialContention(t *testing.T) {
	for _, deleting := range []bool{false, true} {
		t.Run(map[bool]string{false: "rename", true: "delete"}[deleting], func(t *testing.T) {
			f := teamLifecycleOperationFixture(t, true)
			r := teamLifecycleOperationRequest(t, f)
			s := slugNativeOperationService(t, f.service)
			if deleting {
				if _, err := s.UpdateTeam(f.ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			results := make(chan organization.StoreResult, 2)
			var wg sync.WaitGroup
			for range 2 {
				wg.Go(func() {
					<-start
					var out organization.StoreResult
					if deleting {
						out, _ = s.DeleteTeam(f.ctx, teamDeleteOperationRequest(r), "127.0.0.1")
					} else {
						out, _ = s.UpdateTeam(f.ctx, r, "127.0.0.1")
					}
					results <- out
				})
			}
			close(start)
			wg.Wait()
			close(results)
			var winner organization.StoreResult
			for out := range results {
				if out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					if winner.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(winner, out) {
						t.Fatal("initial contenders returned different successful originals")
					}
					winner = out
				}
			}
			if winner.Receipt.Binding.CommandID == "" {
				t.Fatal("neither initial contender committed")
			}
			op := organization.UpdateTeam
			epoch := 5
			if deleting {
				op = organization.DeleteTeam
				epoch = 6
			}
			var effects, actualEpoch int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE operation=$1),(SELECT version FROM organization.organizations)`, string(op)).Scan(&effects, &actualEpoch); err != nil || effects != 1 || actualEpoch != epoch {
				t.Fatal("initial contention duplicated effects before any repair", err)
			}
		})
	}
}
