package organization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestLifecycleOperationRecoveryRetainsOriginalOwnerScope(t *testing.T) {
	for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
		r := organization.OperationRecoveryRequest{
			Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
			Binding:        identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", TenantID: "tenant", UserID: "owner", ActorID: "owner", ActorKind: authorization.SubjectUser, OperationID: string(op), RecordID: "org", PolicyID: "organization", PolicyVersion: 1, SchemaID: "organization-lifecycle", SchemaVersion: 1, CorrelationID: "original-lifecycle"},
		}
		if err := r.Validate(); err != nil {
			t.Fatal("original archive/restore outcome cannot use neutral recovery", err)
		}
		for name, change := range map[string]func(*organization.OperationRecoveryRequest){
			"foreign tenant":               func(r *organization.OperationRecoveryRequest) { r.Authentication.TenantID = "other" },
			"missing original command":     func(r *organization.OperationRecoveryRequest) { r.Binding.CommandID = "" },
			"wrong lifecycle schema":       func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaID = "organization" },
			"hard delete remains separate": func(r *organization.OperationRecoveryRequest) { r.Binding.OperationID = "identity.organization.delete" },
			"foreign target":               func(r *organization.OperationRecoveryRequest) { r.Binding.UserID = "other" },
		} {
			t.Run(string(op)+"/"+name, func(t *testing.T) {
				changed := r
				change(&changed)
				if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
					t.Fatal("invalid original lifecycle recovery accepted")
				}
			})
		}
	}
}

func lifecycleOperationRequest(t testing.TB) organization.LifecycleOperationRequest {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("original-lifecycle-operation"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	return organization.LifecycleOperationRequest{
		Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		IdempotencyKey: key, OrganizationID: "org", OrganizationVersion: 1, Reason: "maintenance", CorrelationID: "lifecycle",
		Proof: authentication.ReauthenticationProof{Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "owner", Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "organization-action", IssuedAt: at, ExpiresAt: at.Add(5 * time.Minute)}, SessionID: "session", SessionVersion: 1, Action: string(organization.Archive)},
	}
}

func TestLifecycleOperationRequestRetainsBoundedOriginalProof(t *testing.T) {
	r := lifecycleOperationRequest(t)
	for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
		r.Proof.Action = string(op)
		// Syntax validation has no trusted clock. An expired original projection
		// must remain representable for matching-key historical classification;
		// only the native signed/current action owner may authorize execution.
		if err := r.Validate(); err != nil {
			t.Fatal("original lifecycle syntax rejected", err)
		}
	}
	maximum := r
	maximum.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 128))
	maximum.Proof.Proof.Tenant = string(maximum.Authentication.TenantID)
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.CorrelationID = strings.Repeat("c", 128)
	maximum.Reason = strings.Repeat("r", 64)
	maximum.OrganizationVersion = ^uint64(0) - 1
	maximum.Proof.SessionID = strings.Repeat("s", 128)
	maximum.Proof.SessionVersion = ^uint64(0)
	maximum.Proof.Proof.ExpiresAt = maximum.Proof.Proof.IssuedAt.Add(24 * time.Hour)
	if err := maximum.Validate(); err != nil {
		t.Fatal("bounded original lifecycle syntax rejected", err)
	}
	for name, change := range map[string]func(*organization.LifecycleOperationRequest){
		"missing key": func(r *organization.LifecycleOperationRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"invalid bearer": func(r *organization.LifecycleOperationRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
		"missing tenant": func(r *organization.LifecycleOperationRequest) { r.Authentication.TenantID = "" },
		"long tenant": func(r *organization.LifecycleOperationRequest) {
			r.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 129))
		},
		"missing org": func(r *organization.LifecycleOperationRequest) { r.OrganizationID = "" },
		"long org": func(r *organization.LifecycleOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"invalid unicode":       func(r *organization.LifecycleOperationRequest) { r.OrganizationID = "\xff" },
		"missing correlation":   func(r *organization.LifecycleOperationRequest) { r.CorrelationID = "" },
		"long correlation":      func(r *organization.LifecycleOperationRequest) { r.CorrelationID = strings.Repeat("c", 129) },
		"missing version":       func(r *organization.LifecycleOperationRequest) { r.OrganizationVersion = 0 },
		"overflow version":      func(r *organization.LifecycleOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"missing reason":        func(r *organization.LifecycleOperationRequest) { r.Reason = "" },
		"long reason":           func(r *organization.LifecycleOperationRequest) { r.Reason = strings.Repeat("r", 65) },
		"space reason":          func(r *organization.LifecycleOperationRequest) { r.Reason = "not free text" },
		"control reason":        func(r *organization.LifecycleOperationRequest) { r.Reason = "maintenance\n" },
		"missing proof":         func(r *organization.LifecycleOperationRequest) { r.Proof = authentication.ReauthenticationProof{} },
		"foreign proof tenant":  func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.Tenant = "other" },
		"missing proof subject": func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.Subject = "" },
		"short proof id":        func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.ID = "short" },
		"long proof id": func(r *organization.LifecycleOperationRequest) {
			r.Proof.Proof.ID = authentication.ProofID(strings.Repeat("p", 129))
		},
		"foreign proof method": func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.Method = "passkey" },
		"foreign proof assurance": func(r *organization.LifecycleOperationRequest) {
			r.Proof.Proof.Assurance = authentication.Assurance(255)
		},
		"foreign proof purpose":  func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.Purpose = "identity.password.change" },
		"missing proof audience": func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.Audience = "" },
		"control proof audience": func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.Audience = "org\n" },
		"missing issued time":    func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.IssuedAt = time.Time{} },
		"missing expiry":         func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.ExpiresAt = time.Time{} },
		"empty lifetime":         func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.ExpiresAt = r.Proof.Proof.IssuedAt },
		"excess lifetime": func(r *organization.LifecycleOperationRequest) {
			r.Proof.Proof.ExpiresAt = r.Proof.Proof.IssuedAt.Add(24*time.Hour + time.Nanosecond)
		},
		"missing session":         func(r *organization.LifecycleOperationRequest) { r.Proof.SessionID = "" },
		"long session":            func(r *organization.LifecycleOperationRequest) { r.Proof.SessionID = strings.Repeat("s", 129) },
		"space session":           func(r *organization.LifecycleOperationRequest) { r.Proof.SessionID = "with space" },
		"unicode session":         func(r *organization.LifecycleOperationRequest) { r.Proof.SessionID = "sëssion" },
		"missing session version": func(r *organization.LifecycleOperationRequest) { r.Proof.SessionVersion = 0 },
		"foreign action":          func(r *organization.LifecycleOperationRequest) { r.Proof.Action = string(organization.OwnerTransfer) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid lifecycle syntax accepted")
			}
		})
	}
}

func TestLifecycleOperationRequestCustodyDoesNotEscape(t *testing.T) {
	assertLifecycleOperationCustody(t, lifecycleOperationRequest(t))
}

func assertLifecycleOperationCustody(t testing.TB, r organization.LifecycleOperationRequest) {
	t.Helper()
	for _, value := range []any{r, &r} {
		if got := fmt.Sprintf("%+v %#v %s", value, value, value); got != "organization.LifecycleOperationRequest(redacted) organization.LifecycleOperationRequest(redacted) organization.LifecycleOperationRequest(redacted)" {
			t.Fatal("lifecycle request escaped diagnostic redaction")
		}
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("lifecycle custody serialized")
		}
	}
	if _, err := r.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("lifecycle custody exported as text")
	}
}

func FuzzLifecycleOperationRequestBoundary(f *testing.F) {
	for _, value := range []string{"org", "", "\x00", "\xff", "with space", "é", strings.Repeat("x", 128), strings.Repeat("x", 129), strings.Repeat("x", 257)} {
		for field := range uint8(10) {
			f.Add(field, value, uint64(1))
		}
	}
	f.Add(uint8(8), "version", ^uint64(0))
	f.Fuzz(func(t *testing.T, field uint8, value string, version uint64) {
		if len(value) > 4096 {
			return
		}
		r := lifecycleOperationRequest(t)
		switch field % 10 {
		case 0:
			r.OrganizationID = organization.ID(value)
		case 1:
			r.Reason = value
		case 2:
			r.CorrelationID = value
		case 3:
			r.Authentication.Bearer = authentication.NewBearerCredential(value)
		case 4:
			r.Proof.Proof.ID = authentication.ProofID(value)
		case 5:
			r.Proof.Proof.Audience = value
		case 6:
			r.Proof.SessionID = value
		case 7:
			r.Proof.Action = value
		case 8:
			r.OrganizationVersion = version
		case 9:
			r.Proof.SessionVersion = version
		}
		if err := r.Validate(); err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("lifecycle boundary returned an open error")
		}
		assertLifecycleOperationCustody(t, r)
	})
}
