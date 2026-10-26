package postgres_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestTransactionalIndexMigrationsRetainExactNativeIndex(t *testing.T) {
	for name, sources := range map[string][2]migrations.Source{
		"operation lookup": {organizationpg.OperationLookupMigrationSource{Version: 81}, organizationpg.OperationLookupTransactionalMigrationSource{Version: 81}},
		"recipient page":   {organizationpg.InvitationRecipientIndexMigrationSource{Version: 82}, organizationpg.InvitationRecipientIndexTransactionalMigrationSource{Version: 82}},
	} {
		t.Run(name, func(t *testing.T) {
			original, err := sources[0].Load(t.Context())
			if err != nil || len(original) != 1 {
				t.Fatal("original native source unavailable", err)
			}
			steps, err := sources[1].Load(t.Context())
			if err != nil || len(steps) != 1 {
				t.Fatal("transactional native source unavailable", err)
			}
			old, got := original[0], steps[0]
			if strings.Count(old.UpSQL(), "CONCURRENTLY ") != 1 || old.TransactionMode() != migrations.TransactionModeNone || old.DownSQL() != "" {
				t.Fatal("original concurrent contract changed")
			}
			if got.Version() != old.Version() || got.Name() != old.Name()+"_transactional" || got.TransactionMode() != migrations.TransactionModeDefault || got.DownSQL() != "" || got.UpSQL() != strings.Replace(old.UpSQL(), "CONCURRENTLY ", "", 1) || got.Checksum() == old.Checksum() {
				t.Fatal("transactional variant changed index semantics or silently adopted old identity")
			}
			again, err := sources[1].Load(t.Context())
			if err != nil || len(again) != 1 || again[0] != got {
				t.Fatal("transactional identity not deterministic", err)
			}
			// Replacing a returned slice value must not mutate either source.
			steps[0] = migrations.Migration{}
			unchanged, err := sources[0].Load(t.Context())
			if err != nil || len(unchanged) != 1 || unchanged[0] != old {
				t.Fatal("transactional load changed original migration", err)
			}
		})
	}
}

func TestTransactionalIndexMigrationsPreserveBoundsAndContextErrors(t *testing.T) {
	for _, version := range []migrations.Version{0, 1, migrations.Version(math.MaxInt64), migrations.Version(math.MaxInt64) + 1} {
		for _, source := range []migrations.Source{organizationpg.OperationLookupTransactionalMigrationSource{Version: version}, organizationpg.InvitationRecipientIndexTransactionalMigrationSource{Version: version}} {
			valid := version > 0 && version <= migrations.Version(math.MaxInt64)
			steps, err := source.Load(t.Context())
			if valid && (err != nil || len(steps) != 1 || steps[0].Version() != version) || !valid && (!errors.Is(err, organization.ErrInvalidInput) || len(steps) != 0) {
				t.Fatal("native migration version bounds changed", err)
			}
			if steps, err = source.Load(nil); !errors.Is(err, organization.ErrInvalidInput) || len(steps) != 0 {
				t.Fatal("nil context accepted", err)
			}
			for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
				ctx := migrationErrorContext{Context: t.Context(), err: cause}
				steps, err = source.Load(ctx)
				want := cause
				if !valid {
					want = organization.ErrInvalidInput
				}
				if !errors.Is(err, want) || len(steps) != 0 {
					t.Fatal("native validation/context precedence changed", err)
				}
			}
		}
	}
}

type migrationErrorContext struct {
	context.Context
	err error
}

func (c migrationErrorContext) Err() error { return c.err }
