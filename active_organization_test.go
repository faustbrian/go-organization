package organization_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

func activeOrganizationFixture(t *testing.T) (*organization.Service, organization.Authentication, *policyClock, *policyOwner, *recordingPolicy, *policyReader) {
	t.Helper()
	var reader *policyReader
	_, auth, at, owner, policy := policyFixtureRepository(t, organization.TeamConfig{}, organization.DomainConfig{}, func(r *policyReader, o *policyOwner) organization.Repository { reader = r; return o })
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	sessions, err := session.NewOrganizationBearerProfileSessionService(reader, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "organization-test", Clock: at, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}}, []session.AuthenticationKind{session.AuthenticationVerified}, "native-password-organization-v1")
	if err != nil {
		t.Fatal(err)
	}
	service, err := organization.NewActiveOrganizationService(sessions, owner, policy, organization.Config{Clock: at, MaximumDuration: time.Second, PolicyID: "organization", PolicyVersion: 1, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, ValidateCanonicalID: func(context.Context, organization.ID) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return service, auth, at, owner, policy, reader
}

func TestActiveOrganizationPreparesSessionOwnedSelectionAndExplicitClear(t *testing.T) {
	s, auth, _, owner, policy, reader := activeOrganizationFixture(t)
	id, _ := identity.NewCommandID()
	command, err := s.PrepareActiveSet(t.Context(), organization.ActiveOrganizationRequest{Authentication: auth, CommandID: id, SessionID: "session-a", OrganizationID: "org", CorrelationID: "active-set"})
	if err != nil {
		t.Fatal(err)
	}
	x, _ := command.Input()
	transition, err := x.ActiveOrganization.Bindings()
	if err != nil || x.Operation != organization.ActiveSet || x.Binding.RecordID != "session-a" || x.Binding.UserID != "actor" || transition.Source != reader.observation.Session || transition.Selection.OrganizationID != "org" || transition.Selection.Authority.Version != 7 || x.Actor != owner.view.Actor || x.Organization != owner.view.Organization {
		t.Fatal("selection lost exact session or current owner epoch", err)
	}
	scope, err := organization.OrganizationSessionScope("tenant-a", "org")
	if err != nil || transition.Selection.Authority.ScopeKey != scope || transition.Selection.Authority.Version == owner.view.Actor.AuthorizationVersion {
		t.Fatal("selection used membership epoch or foreign scope", err)
	}
	if policy.last.Request.Action != authorization.Action(organization.ActiveSet) || policy.last.Request.Resource.ID != "org" {
		t.Fatal("selection permission did not bind target")
	}
	selected, _ := transition.Successor.Bindings()
	reader.observation.Session = transition.Successor
	reader.observation.Current = selected.Authority
	current, err := s.GetActive(t.Context(), organization.ActiveOrganizationReadRequest{Authentication: auth, CorrelationID: "active-get"})
	if err != nil || !current.Selected || current.SessionID != "session-a" || current.SessionVersion != 2 || current.Organization != owner.view.Organization {
		t.Fatal("selected current read failed", err)
	}
	id, _ = identity.NewCommandID()
	clear, err := s.PrepareActiveSet(t.Context(), organization.ActiveOrganizationRequest{Authentication: auth, CommandID: id, SessionID: "session-a", CorrelationID: "active-clear"})
	if err != nil {
		t.Fatal(err)
	}
	cx, _ := clear.Input()
	cleared, _ := cx.ActiveOrganization.Bindings()
	if cleared.Selection.OrganizationID != "" || cleared.Selection.Authority != (session.AuthorityBinding{}) || cx.Binding.RecordID != "session-a" || cx.Organization.ID != "" {
		t.Fatal("clear invented organization authority")
	}
	_, err = s.Execute(t.Context(), clear, outcomeOwner(func(c organization.Command) (organization.StoreResult, error) {
		x, _ := c.Input()
		return organization.StoreResult{MemberID: "actor", Receipt: identity.CommandResult{Binding: x.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "active-audit", Feature: &identity.FeatureReceipt{Operation: organization.ActiveSet.Descriptor(), BeforeVersion: 2, AfterVersion: 3}}}, nil
	}))
	if err != nil {
		t.Fatal("selection receipt was checked as organization transition", err)
	}
}

func TestActiveOrganizationDeniesWithoutLeakingCurrentState(t *testing.T) {
	for _, variant := range []string{"foreign-session", "removed", "archived", "policy", "expired-policy", "unselected-profile", "wrong-org-epoch"} {
		t.Run(variant, func(t *testing.T) {
			s, auth, at, owner, policy, reader := activeOrganizationFixture(t)
			id, _ := identity.NewCommandID()
			r := organization.ActiveOrganizationRequest{Authentication: auth, CommandID: id, SessionID: "session-a", OrganizationID: "org", CorrelationID: "denied-selection"}
			switch variant {
			case "foreign-session":
				r.SessionID = "foreign-session"
			case "removed":
				owner.view.Actor.Active = false
			case "archived":
				owner.view.Organization.Active = false
			case "policy":
				policy.outcome = authorization.Deny
			case "expired-policy":
				policy.beforeReturn = func() { at.now = at.now.Add(20 * time.Second) }
			case "unselected-profile":
				s, auth, _, _, _ = policyFixture(t)
				r.Authentication = auth
			case "wrong-org-epoch":
				command, err := s.PrepareActiveSet(t.Context(), r)
				if err != nil {
					t.Fatal(err)
				}
				x, _ := command.Input()
				transition, _ := x.ActiveOrganization.Bindings()
				spec, _ := transition.Successor.Bindings()
				reader.observation.Session, reader.observation.Current = transition.Successor, spec.Authority
				owner.view.Organization.Version++
				view, err := s.GetActive(t.Context(), organization.ActiveOrganizationReadRequest{Authentication: auth, CorrelationID: r.CorrelationID})
				if !errors.Is(err, organization.ErrForbidden) || view != (organization.ActiveOrganizationView{}) {
					t.Fatal("stale selection disclosed organization metadata", err)
				}
				return
			}
			command, err := s.PrepareActiveSet(t.Context(), r)
			if !errors.Is(err, organization.ErrForbidden) || command != (organization.Command{}) || owner.writes != 0 {
				t.Fatal("invalid authority reached protected selection", err)
			}
		})
	}
}

func TestActiveOrganizationUnselectedReadExpiryAndOriginalSessionPreserved(t *testing.T) {
	s, auth, at, owner, policy, reader := activeOrganizationFixture(t)
	view, err := s.GetActive(t.Context(), organization.ActiveOrganizationReadRequest{Authentication: auth, CorrelationID: "absent-selection"})
	if err != nil || view.Selected || view.SessionID != "session-a" || view.Organization != (organization.Organization{}) || owner.reads != 0 {
		t.Fatal("unselected read invented membership or metadata", err)
	}
	id, _ := identity.NewCommandID()
	command, err := s.PrepareActiveSet(t.Context(), organization.ActiveOrganizationRequest{Authentication: auth, CommandID: id, SessionID: "session-a", OrganizationID: "org", CorrelationID: "original-selection"})
	if err != nil {
		t.Fatal(err)
	}
	x, _ := command.Input()
	transition, _ := x.ActiveOrganization.Bindings()
	original, _ := transition.Source.Bindings()
	next, _ := transition.Successor.Bindings()
	oldVector, _ := original.Authority.Bindings()
	nextVector, _ := next.Authority.Bindings()
	nextVector.Organization, nextVector.ActiveOrganizationID, nextVector.Session = oldVector.Organization, oldVector.ActiveOrganizationID, oldVector.Session
	if nextVector != oldVector {
		t.Fatal("selection changed another authority")
	}
	next.Version, next.Authority = original.Version, original.Authority
	if next != original || transition.Source != reader.observation.Session || !x.ActiveOrganizationValidUntil.Equal(x.Session.ValidUntil()) || !x.ActiveOrganizationValidUntil.Before(reader.observation.ValidUntil) {
		t.Fatal("selection changed lifetime/provenance or renewed source evidence")
	}
	policy.beforeReturn = func() { at.now = x.ActiveOrganizationValidUntil }
	_, err = s.Execute(t.Context(), command, outcomeOwner(func(organization.Command) (organization.StoreResult, error) {
		t.Fatal("expired original reached work")
		return organization.StoreResult{}, nil
	}))
	if !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("exclusive original expiry was renewed", err)
	}
}

func TestActiveOrganizationRequestScopeRecoveryAndRedaction(t *testing.T) {
	_, auth, _, _, _, _ := activeOrganizationFixture(t)
	key, err := identity.NewIdempotencyKey([]byte("active-selection-key"))
	if err != nil {
		t.Fatal(err)
	}
	r := organization.ActiveOrganizationOperationRequest{Authentication: auth, IdempotencyKey: key, SessionID: "session-a", OrganizationID: "org", CorrelationID: "selection-syntax"}
	if r.Validate() != nil {
		t.Fatal("valid keyed selection denied")
	}
	for _, mutate := range []func(*organization.ActiveOrganizationOperationRequest){func(r *organization.ActiveOrganizationOperationRequest) { r.SessionID = "" }, func(r *organization.ActiveOrganizationOperationRequest) { r.SessionID = strings.Repeat("x", 129) }, func(r *organization.ActiveOrganizationOperationRequest) { r.OrganizationID = "bad org" }, func(r *organization.ActiveOrganizationOperationRequest) { r.IdempotencyKey = identity.IdempotencyKey{} }, func(r *organization.ActiveOrganizationOperationRequest) { r.CorrelationID = "" }} {
		bad := r
		mutate(&bad)
		if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
			t.Fatal("unsafe keyed syntax accepted")
		}
	}
	id, _ := identity.NewCommandID()
	op := organization.ActiveSet.Descriptor()
	b := identity.CommandBinding{CommandID: id, TenantID: auth.TenantID, UserID: "actor", ActorID: "actor", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: "session-a", SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "organization", PolicyVersion: 1, CorrelationID: "selection-syntax"}
	if (organization.OperationRecoveryRequest{Authentication: auth, Binding: b}).Validate() != nil {
		t.Fatal("session-record selection recovery rejected")
	}
	b.UserID = "target"
	if (organization.OperationRecoveryRequest{Authentication: auth, Binding: b}).Validate() == nil {
		t.Fatal("selection recovery accepted nonself subject")
	}
	for _, value := range []any{r, organization.ActiveOrganizationRequest{Authentication: auth, SessionID: "private-session"}, organization.ActiveOrganizationReadRequest{Authentication: auth}} {
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("selection custody serialized", err)
		}
		if strings.Contains(fmt.Sprintf("%+v", value), auth.Bearer.Token()) {
			t.Fatal("selection custody formatted")
		}
	}
	a, _ := organization.OrganizationSessionScope("ab", "c")
	bkey, _ := organization.OrganizationSessionScope("a", "bc")
	other, _ := organization.OrganizationSessionScope("other", "c")
	if a == bkey || a == other || !strings.HasPrefix(a, "organization:") {
		t.Fatal("organization scope aliases tenant/organization tuples")
	}
}

func TestActiveOrganizationReadDenialsReturnNoSelection(t *testing.T) {
	for _, variant := range []string{"removed", "archived", "foreign-tenant", "foreign-member", "policy", "late-policy", "revoked", "cookie"} {
		t.Run(variant, func(t *testing.T) {
			s, auth, at, owner, policy, reader := activeOrganizationFixture(t)
			id, _ := identity.NewCommandID()
			command, err := s.PrepareActiveSet(t.Context(), organization.ActiveOrganizationRequest{Authentication: auth, CommandID: id, SessionID: "session-a", OrganizationID: "org", CorrelationID: "read-denied"})
			if err != nil {
				t.Fatal(err)
			}
			x, _ := command.Input()
			transition, _ := x.ActiveOrganization.Bindings()
			spec, _ := transition.Successor.Bindings()
			reader.observation.Session, reader.observation.Current = transition.Successor, spec.Authority
			switch variant {
			case "removed":
				owner.view.Actor.Active = false
			case "archived":
				owner.view.Organization.Active = false
			case "foreign-tenant":
				owner.view.Organization.TenantID = "other-tenant"
			case "foreign-member":
				owner.view.Actor.UserID = "other-user"
			case "policy":
				policy.outcome = authorization.Deny
			case "late-policy":
				policy.beforeReturn = func() { at.now = reader.observation.ValidUntil }
			case "revoked":
				reader.observation.Active = false
			case "cookie":
				key, _ := session.NewCSRFKey(1, make([]byte, 32))
				token, _ := session.NewCSRFToken()
				state, stateErr := token.Digest(key, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
				if stateErr != nil {
					t.Fatal(stateErr)
				}
				reader.observation.Session, err = session.NewSessionWithCSRF(spec, state)
				if err != nil {
					t.Fatal(err)
				}
			}
			view, err := s.GetActive(t.Context(), organization.ActiveOrganizationReadRequest{Authentication: auth, CorrelationID: "read-denied"})
			if !errors.Is(err, organization.ErrForbidden) || view != (organization.ActiveOrganizationView{}) {
				t.Fatal("denied read exposed selection", err)
			}
		})
	}
}

func TestActiveOrganizationUnsupportedAuthenticationProfilesFailClosed(t *testing.T) {
	for _, variant := range []string{"verified-other-method", "verified-multifactor-assurance", "factor-present", "passkey-present"} {
		t.Run(variant, func(t *testing.T) {
			s, auth, _, owner, policy, reader := activeOrganizationFixture(t)
			spec, err := reader.observation.Session.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			vector, _ := spec.Authority.Bindings()
			switch variant {
			case "verified-other-method":
				spec.Authentication.Proof.Method = "oauth"
			case "verified-multifactor-assurance":
				spec.Authentication.Proof.Assurance = authentication.AssuranceMultiFactor
			case "factor-present":
				vector.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor", Version: 1}}
			case "passkey-present":
				vector.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey", Version: 1}}
			}
			spec.Authority, err = session.NewAuthoritySnapshot(vector)
			if err != nil {
				t.Fatal(err)
			}
			// Trusted-reader projections isolate this core admission contract;
			// they are not proof of a native login or completed MFA ceremony.
			reader.observation.Session, err = session.NewSession(spec)
			if err != nil {
				t.Fatal(err)
			}
			reader.observation.Current = spec.Authority
			id, _ := identity.NewCommandID()
			command, prepareErr := s.PrepareActiveSet(t.Context(), organization.ActiveOrganizationRequest{Authentication: auth, CommandID: id, SessionID: "session-a", OrganizationID: "org", CorrelationID: "unsupported-selection"})
			view, readErr := s.GetActive(t.Context(), organization.ActiveOrganizationReadRequest{Authentication: auth, CorrelationID: "unsupported-selection"})
			if !errors.Is(prepareErr, organization.ErrForbidden) || !errors.Is(readErr, organization.ErrForbidden) || command != (organization.Command{}) || view != (organization.ActiveOrganizationView{}) || owner.reads != 0 || owner.writes != 0 || policy.calls != 0 {
				t.Fatal("unsupported profile reached protected selection or exposed metadata", prepareErr, readErr)
			}
		})
	}
}

func TestActiveOrganizationMalformedOwnerOutcomeStaysUnknown(t *testing.T) {
	for _, variant := range []string{"organization-receipt", "wrong-version", "wrong-session", "panic"} {
		t.Run(variant, func(t *testing.T) {
			s, auth, _, _, _, _ := activeOrganizationFixture(t)
			id, _ := identity.NewCommandID()
			command, err := s.PrepareActiveSet(t.Context(), organization.ActiveOrganizationRequest{Authentication: auth, CommandID: id, SessionID: "session-a", OrganizationID: "org", CorrelationID: "uncertain-selection"})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			out, err := s.Execute(t.Context(), command, outcomeOwner(func(c organization.Command) (organization.StoreResult, error) {
				calls++
				if variant == "panic" {
					panic("private backend failure")
				}
				x, _ := c.Input()
				r := organization.StoreResult{MemberID: "actor", Receipt: identity.CommandResult{Binding: x.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "active-audit", Feature: &identity.FeatureReceipt{Operation: organization.ActiveSet.Descriptor(), BeforeVersion: 1, AfterVersion: 2}}}
				switch variant {
				case "organization-receipt":
					r.OrganizationID = "org"
				case "wrong-version":
					r.Receipt.Feature.BeforeVersion, r.Receipt.Feature.AfterVersion = 7, 8
				case "wrong-session":
					r.Receipt.Binding.RecordID = "session-b"
				}
				return r, nil
			}))
			if err == nil || calls != 1 || out.OrganizationID != "" || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.Receipt.Binding.CommandID != id || out.Receipt.Binding.RecordID != "session-a" || out.Receipt.Feature.Operation != organization.ActiveSet.Descriptor() {
				t.Fatal("uncertain selection was retried, disclosed, or relabeled", err)
			}
		})
	}
}

func FuzzActiveOrganizationScopeBoundary(f *testing.F) {
	for _, value := range []string{"tenant", "a:b", "", "bad org", "a\x00b", strings.Repeat("x", 128), strings.Repeat("x", 129), "\xff"} {
		f.Add(value, "organization")
	}
	f.Fuzz(func(t *testing.T, tenant, org string) {
		key, err := organization.OrganizationSessionScope(identity.TenantID(tenant), organization.ID(org))
		valid := func(value string) bool {
			if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
				return false
			}
			for _, r := range value {
				if r <= ' ' || r == 127 {
					return false
				}
			}
			return true
		}
		if !valid(tenant) || !valid(org) {
			if !errors.Is(err, organization.ErrInvalidInput) || key != "" {
				t.Fatal("invalid scope input retained")
			}
			return
		}
		if err != nil || len(key) != 77 || !strings.HasPrefix(key, "organization:") {
			t.Fatal("valid scope was not bounded")
		}
		other, err := organization.OrganizationSessionScope(identity.TenantID(tenant), organization.ID(org))
		if err != nil || key != other {
			t.Fatal("scope changed between fresh calls")
		}
	})
}
