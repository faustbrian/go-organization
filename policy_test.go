package organization_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

type policyClock struct{ now time.Time }

func (c *policyClock) Now() time.Time { return c.now }

type policyReader struct{ observation session.SessionObservation }

func (r *policyReader) ObserveSession(context.Context, session.SessionLookup) (session.SessionObservation, error) {
	return r.observation, nil
}

type recordingPolicy struct {
	outcome      authorization.Outcome
	revision     authorization.Revision
	last         authorization.DecisionContext
	calls        int
	beforeReturn func()
	err          error
}

func (p *recordingPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	p.last, p.calls = c, p.calls+1
	if p.beforeReturn != nil {
		p.beforeReturn()
	}
	if p.err != nil {
		return authorization.Decision{}, p.err
	}
	return authorization.Decision{Outcome: p.outcome, Revision: p.revision}, nil
}

type policyOwner struct {
	view             organization.View
	reads, writes    int
	organizations    []organization.OrganizationListEntry
	listReads        int
	listError        error
	listQuery        organization.OrganizationListQuery
	beforeListReturn func()
}

func (o *policyOwner) Read(context.Context, organization.Query) (organization.View, error) {
	o.reads++
	return o.view, nil
}
func (o *policyOwner) Execute(_ context.Context, c organization.Command) (organization.StoreResult, error) {
	o.writes++
	x, err := c.Input()
	if err != nil {
		return organization.StoreResult{}, err
	}
	return organization.StoreResult{OrganizationID: x.Organization.ID, MemberID: x.TargetUser.ID, Receipt: identity.CommandResult{Binding: x.Binding, Outcome: identity.CommitOutcomeCommitted, Feature: &identity.FeatureReceipt{Operation: x.Operation.Descriptor(), BeforeVersion: x.Organization.Version, AfterVersion: x.Organization.Version + 1}}}, nil
}
func (*policyOwner) Recover(context.Context, identity.CommandID) (organization.StoreResult, error) {
	return organization.StoreResult{}, organization.ErrForbidden
}

// This is a core-policy unit fixture, not proof of native identity/session
// persistence or sign-in. The PostgreSQL suite must use those actual owners.
func policyFixture(t *testing.T, selectedTeams ...organization.TeamConfig) (*organization.Service, organization.Authentication, *policyClock, *policyOwner, *recordingPolicy) {
	var teams organization.TeamConfig
	if len(selectedTeams) > 0 {
		teams = selectedTeams[0]
	}
	return policyFixtureConfig(t, teams, organization.DomainConfig{})
}

func policyFixtureConfig(t *testing.T, teams organization.TeamConfig, domains organization.DomainConfig) (*organization.Service, organization.Authentication, *policyClock, *policyOwner, *recordingPolicy) {
	t.Helper()
	c := &policyClock{now: time.Date(2026, 10, 18, 12, 0, 1, 0, time.UTC)}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	bind := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind("global"), Tenant: bind("tenant"), User: bind("user"), Identifier: bind("identifier"), Credential: bind("credential"), SessionFamily: bind("family"), Session: bind("session"), Authorization: bind("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(key, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	issued := c.now.Add(-time.Second)
	record, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "actor", Audience: "organization-test", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: issued, LastActivityAt: issued, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "actor", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "organization-test", IssuedAt: issued.Add(-time.Second), ExpiresAt: issued.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	r := &policyReader{observation: session.SessionObservation{Session: record, Current: authority, Active: true, ReadStartedAt: c.now, ValidUntil: c.now.Add(20 * time.Second)}}
	sessions, err := session.NewSessionService(r, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "organization-test", Clock: c, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	owner := &policyOwner{view: organization.View{Organization: organization.Organization{ID: "org", TenantID: "tenant-a", Slug: "example", Name: "Example", Version: 7, Active: true}, Actor: organization.Member{OrganizationID: "org", TenantID: "tenant-a", UserID: "actor", Role: organization.RoleOwner, Version: 1, AuthorizationVersion: 1, Active: true}, Target: organization.Member{OrganizationID: "org", TenantID: "tenant-a", UserID: "target", Role: organization.RoleOwner, Version: 2, AuthorizationVersion: 1, Active: true}, TargetUser: identity.User{ID: "target", TenantID: "tenant-a", Status: identity.StatusActive, Version: 3}, OwnerCount: 2}}
	policy := &recordingPolicy{outcome: authorization.Allow, revision: 1}
	service, err := organization.NewService(sessions, owner, policy, organization.Config{Clock: c, MaximumDuration: time.Second, PolicyID: "organization", PolicyVersion: 1, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams, Domains: domains, ValidateCanonicalID: func(context.Context, organization.ID) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return service, organization.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential(wire)}, c, owner, policy
}

func memberRequest(t *testing.T, a organization.Authentication) organization.MemberRequest {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return organization.MemberRequest{Authentication: a, CommandID: id, OrganizationID: "org", UserID: "target", OrganizationVersion: 7, MemberVersion: 2, CorrelationID: "membership-test"}
}

func TestCreatePreservesCanonicalIDAndOriginalAdmission(t *testing.T) {
	s, a, c, owner, _ := policyFixture(t)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	command, err := s.PrepareCreate(t.Context(), organization.CreateRequest{Authentication: a, CommandID: id, ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Slug: "canonical", Name: "Canonical", CorrelationID: "create"})
	if err != nil {
		t.Fatal(err)
	}
	input, err := command.Input()
	if err != nil {
		t.Fatal(err)
	}
	if input.Organization.ID != "01ARZ3NDEKTSV4RRFFQ69G5FAV" || input.Binding.CommandID != id || input.Binding.UserID != "actor" || input.Binding.ActorID != "actor" {
		t.Fatal("canonical owner/actor/command changed")
	}
	c.now = input.Session.ValidUntil()
	if _, err = s.Execute(t.Context(), command, owner); !errors.Is(err, organization.ErrForbidden) || owner.writes != 0 {
		t.Fatal("expired original admission entered mutation")
	}
}

func TestRemovedActorAndLastOwnerFailClosed(t *testing.T) {
	for _, scenario := range []string{"removed-actor", "last-owner", "foreign-target", "stale-policy", "suspended-target-removal"} {
		t.Run(scenario, func(t *testing.T) {
			s, a, _, owner, policy := policyFixture(t)
			r := memberRequest(t, a)
			want := organization.ErrForbidden
			switch scenario {
			case "removed-actor":
				owner.view.Actor.Active = false
			case "last-owner":
				owner.view.OwnerCount = 1
				want = organization.ErrLastOwner
			case "foreign-target":
				owner.view.TargetUser.TenantID = "other"
			case "stale-policy":
				policy.revision = 2
			case "suspended-target-removal":
				owner.view.TargetUser.Status = identity.StatusSuspended
				want = nil
			}
			command, err := s.PrepareRemoveMember(t.Context(), r)
			if want == nil {
				if err != nil {
					t.Fatal("suspended target membership became undeletable", err)
				}
				if _, err = command.Input(); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, want) {
				t.Fatalf("wrong denial %v", err)
			}
			if owner.writes != 0 {
				t.Fatal("preparation mutated state")
			}
		})
	}
}

func TestMemberCommandSeparatesActorTargetAndFencesVersion(t *testing.T) {
	s, a, _, owner, policy := policyFixture(t)
	r := memberRequest(t, a)
	command, err := s.PrepareRemoveMember(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	x, err := command.Input()
	if err != nil {
		t.Fatal(err)
	}
	if x.Binding.ActorID != "actor" || x.Binding.UserID != "target" || x.TargetUser.Version != 3 || x.Target.Version != 2 || x.Organization.Version != 7 {
		t.Fatal("actor target or optimistic versions conflated")
	}
	if policy.last.Request.Tenant != "tenant-a" || policy.last.Request.Resource.ID != "org" || policy.last.Request.Subject.ID != "actor" || policy.last.Request.Action != authorization.Action(organization.RemoveMember) {
		t.Fatal("policy scope substituted")
	}
	r.OrganizationVersion = 6
	if _, err = s.PrepareRemoveMember(t.Context(), r); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("stale organization version accepted")
	}
	if owner.writes != 0 {
		t.Fatal("preparation wrote state")
	}
}

func TestReadRejectsForeignProjectionAndDeniedPolicy(t *testing.T) {
	for _, scenario := range []string{"removed", "foreign", "denied", "unordered"} {
		t.Run(scenario, func(t *testing.T) {
			s, a, _, o, p := policyFixture(t)
			switch scenario {
			case "removed":
				o.view.Actor.Active = false
			case "foreign":
				o.view.Organization.TenantID = "other"
			case "denied":
				p.outcome = authorization.Deny
			case "unordered":
				m := o.view.Target
				m.UserID = "z"
				n := m
				n.UserID = "a"
				o.view.Members = []organization.Member{m, n}
			}
			if _, err := s.ListMembers(t.Context(), organization.ReadRequest{Authentication: a, OrganizationID: "org", Limit: 10, CorrelationID: "read"}); err == nil {
				t.Fatal("unsafe read projection accepted")
			}
		})
	}
}

func TestReadWithholdsViewWhenPolicyOutlivesAdmission(t *testing.T) {
	for _, operation := range []string{"get", "list"} {
		for _, scenario := range []string{"expired", "cancelled"} {
			t.Run(operation+"/"+scenario, func(t *testing.T) {
				s, a, clock, owner, policy := policyFixture(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				want := organization.ErrForbidden
				policy.beforeReturn = func() { clock.now = clock.now.Add(20 * time.Second) }
				if scenario == "cancelled" {
					policy.beforeReturn, want = cancel, context.Canceled
				}
				request := organization.ReadRequest{Authentication: a, OrganizationID: "org", CorrelationID: "read"}
				read := s.Get
				if operation == "list" {
					read, request.Limit = s.ListMembers, 10
				}
				view, err := read(ctx, request)
				if !errors.Is(err, want) || view.Organization.ID != "" || len(view.Members) != 0 {
					t.Fatal("policy returned an organization view after original admission ended", err)
				}
				if owner.reads != 1 || policy.calls != 1 {
					t.Fatal("test did not reach the post-read policy boundary")
				}
			})
		}
	}
}
