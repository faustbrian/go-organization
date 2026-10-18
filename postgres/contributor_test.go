package postgres_test

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// Merely implementing the contributor interface cannot manufacture a live
// coordinator invocation or permit organization SQL through a zero Work.
func TestContributorRejectsUnownedMutationAndRecovery(t *testing.T) {
	participant := new(organizationpg.Contributor)
	if result, err := participant.ApplyFeature(t.Context(), kernel.Work{}, identity.Command{}); err == nil || result != (identity.FeatureReceipt{}) {
		t.Fatal("unowned mutation accepted")
	}
	if result, err := participant.RecoverParticipant(t.Context(), kernel.RecoveryWork{}); err == nil || result != kernel.RecoveryUnknown {
		t.Fatal("unowned recovery accepted")
	}
}
