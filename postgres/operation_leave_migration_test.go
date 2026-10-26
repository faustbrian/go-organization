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

func TestLeaveOperationLookupMigrationVariants(t *testing.T) {
	for _, version := range []migrations.Version{0, 1, migrations.Version(math.MaxInt64), migrations.Version(math.MaxInt64) + 1} {
		concurrent := organizationpg.LeaveOperationLookupMigrationSource{Version: version}
		transactional := organizationpg.LeaveOperationLookupTransactionalMigrationSource{Version: version}
		for _, source := range []migrations.Source{concurrent, transactional} {
			steps, err := source.Load(t.Context())
			valid := version > 0 && version <= migrations.Version(math.MaxInt64)
			if valid && (err != nil || len(steps) != 1) || !valid && (!errors.Is(err, organization.ErrInvalidInput) || len(steps) != 0) {
				t.Fatal("leave index version validation", err)
			}
			if _, err := source.Load(nil); !errors.Is(err, organization.ErrInvalidInput) {
				t.Fatal("nil context accepted", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			_, err = source.Load(ctx)
			if valid && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation ignored", err)
			}
		}
		if version == 1 {
			a, _ := concurrent.Load(t.Context())
			b, _ := transactional.Load(t.Context())
			if a[0].TransactionMode() != migrations.TransactionModeNone || b[0].TransactionMode() != migrations.TransactionModeDefault || b[0].Name() != a[0].Name()+"_transactional" || b[0].UpSQL() != strings.Replace(a[0].UpSQL(), "CONCURRENTLY ", "", 1) || a[0].Checksum() == b[0].Checksum() || a[0].DownSQL() != "" || b[0].DownSQL() != "" {
				t.Fatal("leave index variant changed identity or semantics")
			}
		}
	}
}
