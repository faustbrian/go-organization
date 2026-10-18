package organization_test

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

type outcomeOwner func(organization.Command) (organization.StoreResult, error)

func (f outcomeOwner) Execute(_ context.Context, c organization.Command) (organization.StoreResult, error) {
	return f(c)
}
func (outcomeOwner) Recover(context.Context, identity.CommandID) (organization.StoreResult, error) {
	return organization.StoreResult{}, organization.ErrForbidden
}

func TestMutationPanicRetainsUnknownOriginalCommand(t *testing.T) {
	s, a, _, _, _ := policyFixture(t)
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.PrepareCreate(t.Context(), organization.CreateRequest{Authentication: a, CommandID: id, ID: "org-new", Slug: "new", Name: "New", CorrelationID: "new"})
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.Execute(t.Context(), c, outcomeOwner(func(organization.Command) (organization.StoreResult, error) {
		panic("private storage failure after commit attempt")
	}))
	var unknown identity.UnknownCommitError
	if !errors.As(e, &unknown) || unknown.CommandID != id || r.Receipt.Outcome != identity.CommitOutcomeUnknown || r.Receipt.Binding.CommandID != id {
		t.Fatal("panic invented noncommit or lost original unknown correlation")
	}
}

func TestMutationRejectsFabricatedSuccessfulFeatureReceipt(t *testing.T) {
	s, a, _, o, _ := policyFixture(t)
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.PrepareCreate(t.Context(), organization.CreateRequest{Authentication: a, CommandID: id, ID: "org-new", Slug: "new", Name: "New", CorrelationID: "new"})
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.Execute(t.Context(), c, outcomeOwner(func(c organization.Command) (organization.StoreResult, error) {
		r, e := o.Execute(t.Context(), c)
		r.Receipt.Feature.Operation = organization.RemoveMember.Descriptor()
		return r, e
	}))
	if !errors.Is(e, organization.ErrUnavailable) {
		t.Fatal("fabricated feature receipt accepted")
	}
}
