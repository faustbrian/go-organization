package postgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

// This is a pure native command-mapping fixture, not persistence or sign-in
// evidence. Get mints the opaque session observation exactly once, so changing
// the reason cannot accidentally change its original acceptance deadline.
func TestInvitationExpiryMappingBindsOnlyChangedReason(t *testing.T) {
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
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
	issued := at.Add(-time.Second)
	record, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "actor", Audience: "organization-test", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: issued, LastActivityAt: issued, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "actor", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "organization-test", IssuedAt: issued.Add(-time.Second), ExpiresAt: issued.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	reader := expiryMappingReader{observation: session.SessionObservation{Session: record, Current: authority, Active: true, ReadStartedAt: at, ValidUntil: at.Add(20 * time.Second)}}
	sessions, err := session.NewSessionService(reader, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "organization-test", Clock: expiryMappingClock{at: at}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := sessions.Get(t.Context(), session.GetRequest{TenantID: "tenant-a", Credential: credential})
	if err != nil || frozen.ValidateAt(at) != nil {
		t.Fatal("session owner did not mint a valid frozen observation", err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := organization.InvitationExpire.Descriptor()
	input := organization.CommandInput{Operation: organization.InvitationExpire, Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "actor", ActorID: "actor", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: "invitation-a", SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "organization", PolicyVersion: 1, CorrelationID: "reason-intent"}, Session: frozen, Bearer: auth.NewBearerCredential(wire), Organization: organization.Organization{ID: "org", TenantID: "tenant-a", Version: 7, Active: true}, Actor: organization.Member{OrganizationID: "org", TenantID: "tenant-a", UserID: "actor", Role: organization.RoleOwner, Version: 1, AuthorizationVersion: 1, Active: true}, TargetUser: identity.User{ID: "actor", TenantID: "tenant-a"}, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Invitation: organization.InvitationInput{Record: organization.Invitation{ID: "invitation-a", OrganizationID: "org", TenantID: "tenant-a", RecipientUserID: "recipient", RecipientIdentifierID: "recipient-email", RecipientIdentifierVersion: 1, CreatedBy: "actor", Role: organization.RoleMember, Status: organization.InvitationPending, Version: 1, ExpiresAt: at.Add(time.Hour)}, ExpirationReason: "security-withdrawal"}}
	mapInput := func(x organization.CommandInput) identity.FeatureCommandSpec {
		t.Helper()
		p := invitationPhase{input: x}
		if err := p.mapCommand(); err != nil {
			t.Fatal(err)
		}
		spec, ok := p.command.Feature()
		if !ok {
			t.Fatal("mapped command lost feature intent")
		}
		return spec
	}
	before := mapInput(input)
	if !reflect.DeepEqual(before, mapInput(input)) {
		t.Fatal("identical frozen input changed mapped intent")
	}
	changed := input
	changed.Invitation.ExpirationReason = "administrative-cleanup"
	after := mapInput(changed)
	if reflect.DeepEqual(before, after) {
		t.Fatal("changed expiry reason did not change mapped command intent")
	}
	if before.Binding != after.Binding || before.Operation != after.Operation || len(before.Fields) != len(after.Fields) {
		t.Fatal("reason change altered unrelated command shape")
	}
	differences := 0
	for i, field := range before.Fields {
		other := after.Fields[i]
		if reflect.DeepEqual(field, other) {
			continue
		}
		differences++
		if field.Name != "organization.expiry-reason" || other.Name != field.Name || field.Value.Kind != identity.FeatureText || other.Value.Kind != identity.FeatureText || field.Value.Text != "security-withdrawal" || other.Value.Text != "administrative-cleanup" {
			t.Fatal("reason-only input changed an unrelated mapped field")
		}
	}
	if differences != 1 {
		t.Fatal("reason-only input did not change exactly one mapped field")
	}
}

type expiryMappingClock struct{ at time.Time }

func (c expiryMappingClock) Now() time.Time { return c.at }

type expiryMappingReader struct{ observation session.SessionObservation }

func (r expiryMappingReader) ObserveSession(context.Context, session.SessionLookup) (session.SessionObservation, error) {
	return r.observation, nil
}
