//go:build integration

package consumer_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// These unchanged private fixture helpers are retained on each side of the
// test-module boundary; they add no production API, store or authority.
type migrationList []migrations.Migration

func (s migrationList) Load(ctx context.Context) ([]migrations.Migration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]migrations.Migration(nil), s...), nil
}

func commandID(t *testing.T) identity.CommandID {
	t.Helper()
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	return id
}

func mustRoleRecovery(t *testing.T, p organizationpg.PreparedCommand) organizationpg.Recovery {
	t.Helper()
	r, e := p.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	return r
}

type nativeDomainObserver struct {
	calls atomic.Int32
	ttl   time.Duration
}

func (o *nativeDomainObserver) ObserveDomain(ctx context.Context, claim organization.DomainClaim) (organization.DomainObservation, error) {
	if err := ctx.Err(); err != nil {
		return organization.DomainObservation{}, err
	}
	o.calls.Add(1)
	at := time.Now().UTC().Truncate(time.Microsecond)
	ttl := o.ttl
	if ttl == 0 {
		ttl = time.Hour
	}
	return organization.DomainObservation{Claim: claim, Method: organization.DomainDNS, ObservedAt: at, ExpiresAt: at.Add(ttl), Verified: true}, nil
}

func evidenceRecovery(t *testing.T, c organization.DomainEvidenceCommand) organizationpg.Recovery {
	t.Helper()
	x, err := c.Command().Input()
	if err != nil {
		t.Fatal(err)
	}
	return organizationpg.Recovery{Binding: x.Binding}
}
