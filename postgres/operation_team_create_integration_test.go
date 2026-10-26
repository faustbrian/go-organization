//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"sync"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func teamCreateOperationFixture(t *testing.T) *orgFixture {
	t.Helper()
	f := teamFixture(t)
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("team_create_operation")
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
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("existing original-key migrations", err)
	}
	return f
}

func teamCreateRequest(t *testing.T, f *orgFixture, tenant, team, label string, epoch uint64) organization.CreateTeamOperationRequest {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("original-team-" + label))
	if err != nil {
		t.Fatal(err)
	}
	return organization.CreateTeamOperationRequest{Authentication: f.auth(tenant, "owner"), IdempotencyKey: key, OrganizationID: metadataOrganization, TeamID: organization.ID(team), OrganizationVersion: epoch, Name: "Engineering", CorrelationID: "original-team-create"}
}

func invokeTeamCreate(t *testing.T, s *organizationpg.OperationService, ctx context.Context, r organization.CreateTeamOperationRequest) (organization.StoreResult, error) {
	t.Helper()
	operation, ok := any(s).(teamCreateOperation)
	if !ok {
		t.Fatal("native original-key team creation is missing")
	}
	return operation.CreateTeam(ctx, r, "127.0.0.1")
}

func TestCreateTeamOperationOriginalAndCurrentAuthority(t *testing.T) {
	f := teamCreateOperationFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	r := teamCreateRequest(t, f, tenant, "engineering", "first", 2)
	service := slugNativeOperationService(t, f.service)
	original, err := invokeTeamCreate(t, service, f.ctx, r)
	if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted || original.Receipt.Feature == nil || original.Receipt.Feature.Operation != organization.CreateTeam.Descriptor() || original.Receipt.Feature.BeforeVersion != 2 || original.Receipt.Feature.AfterVersion != 3 {
		t.Fatal("original-key team creation did not commit", err)
	}
	r.CorrelationID = "reconstructed-attempt"
	for range 2 {
		got, err := invokeTeamCreate(t, slugNativeOperationService(t, f.service), f.ctx, r)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("team retry lost actual original", err)
		}
	}
	if got, err := service.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal("explicit team original recovery", err)
	}
	for name, change := range map[string]func(*organization.CreateTeamOperationRequest){
		"team":         func(r *organization.CreateTeamOperationRequest) { r.TeamID = "other" },
		"name":         func(r *organization.CreateTeamOperationRequest) { r.Name = "Another name" },
		"epoch":        func(r *organization.CreateTeamOperationRequest) { r.OrganizationVersion++ },
		"organization": func(r *organization.CreateTeamOperationRequest) { r.OrganizationID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if _, err := invokeTeamCreate(t, service, f.ctx, changed); !errors.Is(err, organization.ErrConflict) {
				t.Fatal("changed original intent did not conflict", err)
			}
		})
	}
	for _, actor := range []string{"member", "outsider"} {
		changed := r
		changed.Authentication = f.auth(tenant, actor)
		if got, err := invokeTeamCreate(t, service, f.ctx, changed); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("unauthorized actor adopted team history", actor, err)
		}
	}
	foreign := r
	foreign.Authentication = f.auth("org-test-scope", "owner")
	if got, err := invokeTeamCreate(t, service, f.ctx, foreign); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign tenant adopted team history", err)
	}
	view, err := f.service.ListTeams(f.ctx, organization.TeamReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, Limit: 10, CorrelationID: "created-team-read"})
	if err != nil || len(view.Teams) != 1 || view.Teams[0].ID != r.TeamID || view.Teams[0].Name != r.Name || view.Teams[0].Version != 1 || view.Organization.Version != 3 {
		t.Fatal("native team primary differs from chosen intent", err)
	}
	var memberships int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.team_memberships WHERE tenant_id=$1 AND organization_id=$2`, tenant, string(r.OrganizationID)).Scan(&memberships); err != nil || memberships != 0 {
		t.Fatal("team creation implicitly added members", err)
	}
	id, err := base64.RawURLEncoding.DecodeString(string(original.Receipt.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var effects, events, audits int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.team.create'),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$2 AND m.topic='team.created.v1'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$2 AND r.action='identity.organization.create_team' AND r.outcome=1)`, tenant, id).Scan(&effects, &events, &audits)
	if err != nil || effects != 1 || events != 1 || audits != 1 {
		t.Fatal("team repetition duplicated or lost required effects", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='owner'`, tenant); err != nil {
		t.Fatal(err)
	}
	if got, err := invokeTeamCreate(t, service, f.ctx, r); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("revoked session disclosed original team", err)
	}
}

func TestCreateTeamOperationLimitsRollbackAndContention(t *testing.T) {
	for _, variant := range []string{"limits", "rollback", "contention"} {
		t.Run(variant, func(t *testing.T) {
			f := teamCreateOperationFixture(t)
			tenant := "org-test-basic"
			f.create(t, tenant)
			service := slugNativeOperationService(t, f.service)
			r := teamCreateRequest(t, f, tenant, "engineering", variant, 1)
			if variant == "rollback" {
				if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.fail_team_create() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='team.created.v1' THEN RAISE EXCEPTION 'controlled team effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_team_create BEFORE INSERT ON outbox_messages FOR EACH ROW EXECUTE FUNCTION organization.fail_team_create()`); err != nil {
					t.Fatal(err)
				}
				out, failure := invokeTeamCreate(t, service, f.ctx, r)
				if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fail_team_create ON outbox_messages; DROP FUNCTION organization.fail_team_create()`); err != nil {
					t.Fatal(err)
				}
				if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("required effect failure committed team", failure)
				}
				got, err := invokeTeamCreate(t, slugNativeOperationService(t, f.service), f.ctx, r)
				if !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(got, out) {
					t.Fatal("same key reexecuted rolled-back original", err)
				}
				var teams, version, effects int
				err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.teams WHERE tenant_id=$1),(SELECT version FROM organization.organizations WHERE tenant_id=$1),(SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.team.create')`, tenant).Scan(&teams, &version, &effects)
				if err != nil || teams != 0 || version != 1 || effects != 0 {
					t.Fatal("rollback retained team/epoch/effect", err)
				}
				return
			}
			if variant == "contention" {
				start := make(chan struct{})
				var wg sync.WaitGroup
				for range 2 {
					wg.Go(func() { <-start; _, _ = invokeTeamCreate(t, service, f.ctx, r) })
				}
				close(start)
				wg.Wait()
			}
			original, err := invokeTeamCreate(t, service, f.ctx, r)
			if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("team original unavailable", err)
			}
			if variant == "limits" {
				stale := teamCreateRequest(t, f, tenant, "stale", "stale", 1)
				if _, err := invokeTeamCreate(t, service, f.ctx, stale); !errors.Is(err, organization.ErrConflict) {
					t.Fatal("stale original epoch admitted", err)
				}
				second := teamCreateRequest(t, f, tenant, "second", "second", 2)
				if got, err := invokeTeamCreate(t, service, f.ctx, second); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("second permitted team failed", err)
				}
				over := teamCreateRequest(t, f, tenant, "over", "over", 3)
				if got, err := invokeTeamCreate(t, service, f.ctx, over); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("native team limit bypassed", err)
				}
			}
			var teams, effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.teams WHERE tenant_id=$1),(SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.team.create')`, tenant).Scan(&teams, &effects); err != nil || teams != effects || variant == "contention" && teams != 1 || variant == "limits" && teams != 2 {
				t.Fatal("team count and actual effects diverged", err)
			}
		})
	}
}
