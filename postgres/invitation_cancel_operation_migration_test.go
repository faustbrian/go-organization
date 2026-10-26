package postgres_test

import (
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestInvitationCancelOperationMigrationBoundsAndCancellation(t *testing.T) {
	for _, version := range []migrations.Version{0, 1, migrations.Version(math.MaxInt64), migrations.Version(math.MaxInt64) + 1} {
		source := organizationpg.InvitationCancelOperationMigrationSource{Version: version}
		valid := version > 0 && version <= migrations.Version(math.MaxInt64)
		steps, err := source.Load(t.Context())
		if valid && (err != nil || len(steps) != 1 || steps[0].Version() != version) || !valid && (!errors.Is(err, organization.ErrInvalidInput) || len(steps) != 0) {
			t.Fatal("invalid cancellation migration version contract", err)
		}
		if steps, err := source.Load(nil); !errors.Is(err, organization.ErrInvalidInput) || len(steps) != 0 {
			t.Fatal("nil migration context accepted", err)
		}
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			steps, err := source.Load(migrationErrorContext{Context: t.Context(), err: cause})
			want := cause
			if !valid {
				want = organization.ErrInvalidInput
			}
			if !errors.Is(err, want) || len(steps) != 0 {
				t.Fatal("migration returned partial work or lost context error", err)
			}
		}
	}
}

func TestInvitationCancelOperationMigrationReturnsDetachedForwardWork(t *testing.T) {
	source := organizationpg.InvitationCancelOperationMigrationSource{Version: 7010}
	steps, err := source.Load(t.Context())
	if err != nil || len(steps) != 1 {
		t.Fatal("cancellation migration unavailable", err)
	}
	original := steps[0]
	if original.TransactionMode() != migrations.TransactionModeDefault || original.DownSQL() != "" || original.UpSQL() == "" {
		t.Fatal("cancellation migration lost transactional forward-only contract")
	}
	steps[0] = migrations.Migration{}
	again, err := source.Load(t.Context())
	if err != nil || len(again) != 1 || again[0] != original {
		t.Fatal("caller mutation changed immutable migration identity", err)
	}
}
