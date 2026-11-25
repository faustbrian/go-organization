//go:build integration

package postgres_test

import (
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func (f directorySuccessorFixture) authorizedCurrentOwner(t *testing.T) organization.CredentialAuthorityObservation {
	t.Helper()
	_, err := f.fixture.service.Get(f.fixture.ctx, organization.ReadRequest{
		Authentication: f.fixture.auth(string(f.source.TenantID), "owner"),
		OrganizationID: f.source.OrganizationID, CorrelationID: "directory-chain-current-owner",
	})
	if err != nil {
		t.Fatal("fresh authenticated owner read denied", err)
	}
	current, err := f.store.ObserveCredentialAuthority(f.fixture.ctx, organization.CredentialAuthorityQuery{
		TenantID: f.source.TenantID, OrganizationID: f.source.OrganizationID,
	})
	if err != nil {
		t.Fatal("read freshly authorized owner facts", err)
	}
	return current
}

func TestDirectoryMembershipSuccessorChainValidatesOriginalOrderedPrefixAfterRestart(t *testing.T) {
	f := newDirectorySuccessorFixture(t)
	original, grant := f.commit(t, f.source, false)
	// A separate already-live source keeps the first member active during
	// the final same-batch withdrawal; it must not force an org-version bump.
	overlap := f.source
	overlap.ConnectionID, overlap.ResourceID = "other-connection", "other-resource"
	_, _ = f.commit(t, overlap, false)
	otherSource := f.source
	otherSource.UserID, otherSource.ResourceID = "second", "second-resource"
	middle, otherGrant := f.commit(t, otherSource, false)
	next, withdrawal := f.commit(t, f.source, true)
	if middle.Version != original.Version+1 || next.Version != original.Version+2 ||
		grant.Binding.CorrelationID != otherGrant.Binding.CorrelationID || grant.Binding.CorrelationID != withdrawal.Binding.CorrelationID {
		t.Fatal("fixture did not commit consecutive children from the same batch")
	}

	restarted, err := organizationpg.NewRepository(f.fixture.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f.store = restarted
	children := []organizationpg.DirectoryMembershipCommittedChild{
		{Source: f.source, Receipt: f.recoverReceipt(t, grant.Binding)},
		{Source: otherSource, Receipt: f.recoverReceipt(t, otherGrant.Binding)},
		{Source: f.source, Receipt: f.recoverReceipt(t, withdrawal.Binding)},
	}
	if !reflect.DeepEqual(children[0].Receipt, grant) || !reflect.DeepEqual(children[1].Receipt, otherGrant) || !reflect.DeepEqual(children[2].Receipt, withdrawal) {
		t.Fatal("independently authorized recovery changed an original child receipt")
	}
	current := f.authorizedCurrentOwner(t)
	if current.Version != next.Version || current.Version != original.Version+2 {
		t.Fatal("overlapping source withdrawal unexpectedly advanced the organization")
	}
	if _, err := f.store.RecoverDirectoryMembershipSuccessor(f.fixture.ctx, f.source, original, children[0].Receipt); err == nil {
		t.Fatal("first historical child unexpectedly qualifies as the current successor")
	}
	if err := f.store.ValidateDirectoryMembershipSuccessorChain(f.fixture.ctx, current, children); err != nil {
		t.Fatal("original ordered historical prefix was rejected after restart", err)
	}
	if children[0].Source != f.source || children[1].Source != otherSource || children[2].Source != f.source ||
		!reflect.DeepEqual(children[0].Receipt, grant) || !reflect.DeepEqual(children[1].Receipt, otherGrant) || !reflect.DeepEqual(children[2].Receipt, withdrawal) {
		t.Fatal("validation rewrote original child evidence")
	}

	for _, mode := range []string{"reordered", "omitted-middle", "duplicate", "source", "command", "correlation", "transition", "unknown", "expired-current", "credential-version"} {
		t.Run(mode, func(t *testing.T) {
			observed := current
			changed := append([]organizationpg.DirectoryMembershipCommittedChild(nil), children...)
			feature := *changed[1].Receipt.Feature
			changed[1].Receipt.Feature = &feature
			switch mode {
			case "reordered":
				changed[0], changed[1] = changed[1], changed[0]
			case "omitted-middle":
				changed = []organizationpg.DirectoryMembershipCommittedChild{changed[0], changed[2]}
			case "duplicate":
				changed[1] = changed[0]
			case "source":
				changed[1].Source.ResourceID = "different-resource"
			case "command":
				changed[1].Receipt.Binding.CommandID = commandID(t)
			case "correlation":
				changed[1].Receipt.Binding.CorrelationID = "different-batch"
			case "transition":
				changed[1].Receipt.Feature.BeforeVersion++
				changed[1].Receipt.Feature.AfterVersion++
			case "unknown":
				changed[1].Receipt.Outcome = identity.CommitOutcomeUnknown
			case "expired-current":
				observed.ReadStartedAt = observed.ReadStartedAt.Add(-time.Minute)
				observed.VerifiedAt = observed.VerifiedAt.Add(-time.Minute)
				observed.ValidUntil = observed.ValidUntil.Add(-time.Minute)
			case "credential-version":
				observed.CredentialVersion++
			}
			if err := f.store.ValidateDirectoryMembershipSuccessorChain(f.fixture.ctx, observed, changed); err == nil {
				t.Fatal("unproven or expired successor chain was accepted")
			}
		})
	}
	if err := f.store.ValidateDirectoryMembershipSuccessorChain(f.fixture.ctx, current, children); err != nil {
		t.Fatal("denied variants damaged the original chain", err)
	}

	f.fixture.add(t, string(f.source.TenantID), "outsider", organization.RoleMember, current.Version)
	ahead := f.authorizedCurrentOwner(t)
	if ahead.Version != current.Version+1 {
		t.Fatal("unrelated owner change did not advance the current version")
	}
	for _, observed := range []organization.CredentialAuthorityObservation{current, ahead} {
		if err := f.store.ValidateDirectoryMembershipSuccessorChain(f.fixture.ctx, observed, children); err == nil {
			t.Fatal("historical child chain absorbed an unrelated owner change")
		}
	}
}
