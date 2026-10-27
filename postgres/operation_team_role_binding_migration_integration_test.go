//go:build integration

package postgres_test

import (
	"errors"
	"strings"
	"testing"

	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestTeamRoleBindingOperationPopulatedLookupMigration(t *testing.T) {
	f, _ := teamRoleBindingOperationFixture(t, false)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version) SELECT translate(rtrim(encode(int8send(n)||int8send(73),'base64'),'='),'+/','-_'),'org-test-basic','01ARZ3NDEKTSV4RRFFQ69G5FAV','owner','owner','identity.organization.role.revoke',decode(repeat('01',32),'hex'),n+10,n+11 FROM generate_series(1::bigint,4000::bigint) n`); err != nil {
		t.Fatal(err)
	}
	steps, err := (organizationpg.TeamRoleBindingRevokeOperationLookupMigrationSource{Version: 325}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	if _, err := blocker.Exec(f.ctx, `LOCK TABLE organization.command_effects IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	blocked, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(f.ctx)
	if _, err := blocked.Exec(f.ctx, `SET LOCAL lock_timeout='50ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = blocked.Exec(f.ctx, steps[0].UpSQL())
	var lock *pgconn.PgError
	if !errors.As(err, &lock) || lock.Code != "55P03" {
		t.Fatal("bounded migration lock budget failed", err)
	}
	if err := blocked.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	var partial bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='organization' AND table_name='command_effects' AND column_name='revoke_team_role_id') OR to_regclass('organization.organization_repeat_team_role_revoke') IS NOT NULL`).Scan(&partial); err != nil || partial {
		t.Fatal("interrupted migration left partial schema", err)
	}
	installTeamRoleBindingOperationMigration(t, f)
	var legacy int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE revoke_team_role_id IS NULL AND revoke_team_role_version IS NULL`).Scan(&legacy); err != nil || legacy != 4005 {
		t.Fatal("populated upgrade invented original correlation", err)
	}
	const insert = `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version,revoke_team_role_id,revoke_team_role_version,revoke_team_id,revoke_team_version,revoke_team_binding_version) VALUES($1,'org-test-basic','01ARZ3NDEKTSV4RRFFQ69G5FAV','owner','owner','identity.organization.role.revoke',decode(repeat('02',32),'hex'),100000,100001,'reader',3,'engineering',2,1)`
	id := commandID(t)
	if _, err := f.pool.Raw().Exec(f.ctx, insert, string(id)); err != nil {
		t.Fatal(err)
	}
	_, err = f.pool.Raw().Exec(f.ctx, insert, string(commandID(t)))
	var duplicate *pgconn.PgError
	if !errors.As(err, &duplicate) || duplicate.Code != "23505" || duplicate.ConstraintName != "organization_repeat_team_role_revoke" {
		t.Fatal("correlated deletion epoch not unique", err)
	}
	for _, sql := range []string{`UPDATE organization.command_effects SET revoke_team_role_version=NULL WHERE command_id=$1`, `UPDATE organization.command_effects SET revoke_team_role_version=18446744073709551615 WHERE command_id=$1`, `UPDATE organization.command_effects SET revoke_team_id=NULL WHERE command_id=$1`, `UPDATE organization.command_effects SET revoke_team_version=NULL WHERE command_id=$1`, `UPDATE organization.command_effects SET revoke_team_version=18446744073709551615 WHERE command_id=$1`, `UPDATE organization.command_effects SET revoke_team_binding_version=18446744073709551615 WHERE command_id=$1`, `UPDATE organization.command_effects SET operation='identity.organization.role.update' WHERE command_id=$1`} {
		if _, err := f.pool.Raw().Exec(f.ctx, sql, string(id)); err == nil {
			t.Fatal("partial/overflow/wrong-operation correlation accepted")
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE organization.command_effects`); err != nil {
		t.Fatal(err)
	}
	rows, err := f.pool.Raw().Query(f.ctx, `EXPLAIN (ANALYZE,BUFFERS) SELECT command_id,revoke_team_role_id,revoke_team_role_version::text,revoke_team_id,revoke_team_version::text,revoke_team_binding_version::text,actor_id,user_id FROM organization.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND before_version=$3::numeric AND operation='identity.organization.role.revoke' AND revoke_team_id IS NOT NULL LIMIT 2`, "org-test-basic", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "100000")
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !strings.Contains(plan.String(), "organization_repeat_team_role_revoke") {
		t.Fatal("exact original lookup missed owned bounded index", err, plan.String())
	}
	var size int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT pg_relation_size('organization.organization_repeat_team_role_revoke')`).Scan(&size); err != nil || size <= 0 {
		t.Fatal(err)
	}
	t.Logf("isolated4000legacy/1correlated effects, partial index%dbytes; exact lookup:\n%s", size, plan.String())
}
