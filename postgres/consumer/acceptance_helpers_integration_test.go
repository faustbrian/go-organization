//go:build integration

package consumer_test

import (
	"context"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// These unchanged private fixture helpers are retained on each side of the
// test-module boundary; they add no production API, store or authority.
type directInvitationAccepter interface {
	Accept(context.Context, organization.InvitationAcceptRequest, string, organization.InvitationAcceptAdmitter) (organization.StoreResult, error)
	RecoverAccept(context.Context, organization.InvitationAcceptRecoveryRequest) (organization.StoreResult, error)
}

type twoPhaseInvitationAccepter interface {
	PrepareAcceptance(context.Context, organization.InvitationAcceptRequest, string) (organization.PreparedInvitationAcceptance, error)
}

func twoPhaseInvitationAcceptance(t testing.TB, source *organizationpg.InvitationService) twoPhaseInvitationAccepter {
	t.Helper()
	service, ok := any(source).(twoPhaseInvitationAccepter)
	if !ok {
		t.Fatal("native invitation acceptance cannot prepare authentic admission before handler middleware")
	}
	return service
}

func directInvitationAcceptance(t testing.TB, source *organizationpg.InvitationService) directInvitationAccepter {
	t.Helper()
	service, ok := any(source).(directInvitationAccepter)
	if !ok {
		t.Fatal("native invitation acceptance has no neutral once/admission/recovery boundary")
	}
	return service
}
