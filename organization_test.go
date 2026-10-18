package organization_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

type noSession struct{ reads int }

func (s *noSession) ObserveSession(context.Context, session.SessionLookup) (session.SessionObservation, error) {
	s.reads++
	return session.SessionObservation{}, nil
}

type denyPolicy struct{ calls int }

func (p *denyPolicy) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	p.calls++
	return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
}

type rejectingOwner struct{ writes, reads int }

func (o *rejectingOwner) Execute(context.Context, organization.Command) (organization.StoreResult, error) {
	o.writes++
	return organization.StoreResult{}, errors.New("private diagnostic")
}

func (o *rejectingOwner) Recover(context.Context, identity.CommandID) (organization.StoreResult, error) {
	o.writes++
	return organization.StoreResult{}, errors.New("private diagnostic")
}

func (o *rejectingOwner) Read(context.Context, organization.Query) (organization.View, error) {
	o.reads++
	return organization.View{}, errors.New("private diagnostic")
}

// A structural session or claimed actor cannot enter organization storage.
// The real session service must authenticate the separately submitted bearer.
func TestCreateDeniesMissingSessionBeforePolicyOrStorage(t *testing.T) {
	reader := &noSession{}
	key, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewSessionService(reader, session.ServiceConfig{
		Profile: session.StorageStatefulOpaque, Audience: "organization-test", Clock: clock.System{},
		MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key},
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, policy := &rejectingOwner{}, &denyPolicy{}
	service, err := organization.NewService(sessions, owner, policy, organization.Config{
		Clock: clock.System{}, MaximumDuration: time.Second, PolicyID: "organization", PolicyVersion: 1,
		MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000,
		ValidateCanonicalID: func(context.Context, organization.ID) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.PrepareCreate(t.Context(), organization.CreateRequest{
		Authentication: organization.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		CommandID:      command, ID: "01JTESTORGANIZATION", Slug: "example", Name: "Example", CorrelationID: "create-test",
	})
	if !errors.Is(err, organization.ErrForbidden) {
		t.Fatalf("missing session must deny, got %v", err)
	}
	if reader.reads != 1 || policy.calls != 0 || owner.reads != 0 || owner.writes != 0 {
		t.Fatal("missing session reached organization policy or storage")
	}
}
