package organization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestDirectOperationRequestsRequireExactKeyedAndRepeatCustody(t *testing.T) {
	key, err := identity.NewIdempotencyKey([]byte("original-organization-operation"))
	if err != nil {
		t.Fatal(err)
	}
	auth := organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}
	create := organization.CreateOperationRequest{Authentication: auth, IdempotencyKey: key, Name: "Example", Slug: "example", CorrelationID: "create"}
	add := organization.AddMemberOperationRequest{Authentication: auth, IdempotencyKey: key, OrganizationID: "organization", UserID: "member", Role: organization.RoleMember, OrganizationVersion: 1, CorrelationID: "add"}
	remove := organization.RemoveMemberOperationRequest{Authentication: auth, OrganizationID: "organization", UserID: "member", OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "remove"}
	for _, request := range []interface{ Validate() error }{create, add, remove} {
		if err := request.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	create.IdempotencyKey = identity.IdempotencyKey{}
	add.IdempotencyKey = identity.IdempotencyKey{}
	remove.MemberVersion = 0
	for _, request := range []interface{ Validate() error }{create, add, remove} {
		if err := request.Validate(); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatalf("invalid original request accepted: %v", err)
		}
	}
}

func TestDirectOperationRequestsRejectHostileOrInconsistentInput(t *testing.T) {
	key, _ := identity.NewIdempotencyKey([]byte("original-organization-operation"))
	auth := organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}
	create := organization.CreateOperationRequest{Authentication: auth, IdempotencyKey: key, Name: "Example", Slug: "example", CorrelationID: "create"}
	for name, change := range map[string]func(*organization.CreateOperationRequest){
		"invalid bearer": func(r *organization.CreateOperationRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
		"missing tenant": func(r *organization.CreateOperationRequest) { r.Authentication.TenantID = "" },
		"long tenant": func(r *organization.CreateOperationRequest) {
			r.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 129))
		},
		"invalid slug":        func(r *organization.CreateOperationRequest) { r.Slug = "Not-Canonical" },
		"control name":        func(r *organization.CreateOperationRequest) { r.Name = "Example\nsecret" },
		"invalid utf8":        func(r *organization.CreateOperationRequest) { r.Name = string([]byte{0xff}) },
		"oversized name":      func(r *organization.CreateOperationRequest) { r.Name = strings.Repeat("n", 257) },
		"missing correlation": func(r *organization.CreateOperationRequest) { r.CorrelationID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			r := create
			change(&r)
			if !errors.Is(r.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid input accepted")
			}
		})
	}
	add := organization.AddMemberOperationRequest{Authentication: auth, IdempotencyKey: key, OrganizationID: "organization", UserID: "member", Role: organization.RoleMember, OrganizationVersion: 1, CorrelationID: "add"}
	for name, change := range map[string]func(*organization.AddMemberOperationRequest){
		"missing organization": func(r *organization.AddMemberOperationRequest) { r.OrganizationID = "" },
		"missing target":       func(r *organization.AddMemberOperationRequest) { r.UserID = "" },
		"unknown role":         func(r *organization.AddMemberOperationRequest) { r.Role = "super-admin" },
		"missing epoch":        func(r *organization.AddMemberOperationRequest) { r.OrganizationVersion = 0 },
		"overflow epoch":       func(r *organization.AddMemberOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"overflow member":      func(r *organization.AddMemberOperationRequest) { r.MemberVersion = ^uint64(0) },
	} {
		t.Run(name, func(t *testing.T) {
			r := add
			change(&r)
			if !errors.Is(r.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func TestDirectOperationRequestsDoNotSerializeCustody(t *testing.T) {
	key, _ := identity.NewIdempotencyKey([]byte("original-organization-operation"))
	auth := organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}
	for _, r := range []any{
		organization.CreateOperationRequest{Authentication: auth, IdempotencyKey: key, Name: "private-name"},
		organization.AddMemberOperationRequest{Authentication: auth, IdempotencyKey: key},
		organization.RemoveMemberOperationRequest{Authentication: auth},
		organization.OperationRecoveryRequest{Authentication: auth},
	} {
		if _, err := json.Marshal(r); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("custody serialized")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if text := fmt.Sprintf(format, r); !strings.Contains(text, "redacted") || strings.Contains(text, auth.Bearer.Token()) || strings.Contains(text, "private-name") {
				t.Fatal("diagnostic leaked request custody")
			}
		}
		if _, err := r.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("custody serialized as text")
		}
	}
}

func TestOperationRecoveryRequestRetainsOriginalScope(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	r := organization.OperationRecoveryRequest{
		Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		Binding:        identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "member", ActorID: "owner", ActorKind: authorization.SubjectUser, OperationID: string(organization.AddMember), RecordID: "org", PolicyID: "organizations", PolicyVersion: 1, SchemaID: "organization-membership", SchemaVersion: 1, CorrelationID: "add"},
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*organization.OperationRecoveryRequest){
		"cross tenant": func(r *organization.OperationRecoveryRequest) { r.Authentication.TenantID = "other" },
		"unselected operation": func(r *organization.OperationRecoveryRequest) {
			r.Binding.OperationID = string(organization.UpdateMember)
		},
		"missing command": func(r *organization.OperationRecoveryRequest) { r.Binding.CommandID = "" },
		"workload actor": func(r *organization.OperationRecoveryRequest) {
			r.Binding.ActorKind = authorization.SubjectServiceAccount
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid recovery scope accepted")
			}
		})
	}
}

func FuzzDirectOperationRequestValidation(f *testing.F) {
	for _, value := range []string{"example", "", "\x00", "\xff", "UPPER", strings.Repeat("x", 63), strings.Repeat("x", 64), strings.Repeat("x", 128), strings.Repeat("x", 129), strings.Repeat("x", 256), strings.Repeat("x", 257)} {
		f.Add(value, uint64(1), uint64(1), uint8(0))
	}
	f.Add("example", ^uint64(0), ^uint64(0), uint8(31))
	f.Fuzz(func(t *testing.T, value string, orgVersion, memberVersion uint64, mode uint8) {
		if len(value) > 4096 {
			return
		}
		key, err := identity.NewIdempotencyKey([]byte("synthetic-fuzz-operation"))
		if err != nil {
			t.Fatal("fuzz key construction failed")
		}
		auth := organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}
		if mode&1 != 0 {
			auth.Bearer = authentication.NewBearerCredential(value)
		}
		if mode&2 != 0 {
			key = identity.IdempotencyKey{}
		}
		role := organization.RoleMember
		if mode&4 != 0 {
			role = organization.Role(value)
		}
		create := organization.CreateOperationRequest{Authentication: auth, IdempotencyKey: key, Name: value, Slug: value, CorrelationID: value}
		add := organization.AddMemberOperationRequest{Authentication: auth, IdempotencyKey: key, OrganizationID: organization.ID(value), UserID: identity.UserID(value), Role: role, OrganizationVersion: orgVersion, MemberVersion: memberVersion, CorrelationID: value}
		remove := organization.RemoveMemberOperationRequest{Authentication: auth, OrganizationID: organization.ID(value), UserID: identity.UserID(value), OrganizationVersion: orgVersion, MemberVersion: memberVersion, CorrelationID: value}
		binding := identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", TenantID: "tenant", UserID: "member", ActorID: "owner", ActorKind: authorization.SubjectUser, OperationID: string(organization.AddMember), RecordID: "org", PolicyID: "organization", PolicyVersion: 1, SchemaID: "organization-membership", SchemaVersion: 1, CorrelationID: value}
		if mode&8 != 0 {
			binding.OperationID = value
		}
		if mode&16 != 0 {
			binding.TenantID = "other"
		}
		recovery := organization.OperationRecoveryRequest{Authentication: auth, Binding: binding}
		for _, request := range []interface{ Validate() error }{create, add, remove, recovery} {
			if err := request.Validate(); err != nil && !errors.Is(err, organization.ErrInvalidInput) {
				t.Fatal("validator returned an unclassified error")
			}
		}
		if create.Validate() == nil && (key == (identity.IdempotencyKey{}) || value == "" || len(value) > 63 || !utf8.ValidString(value)) {
			t.Fatal("create accepted invalid bounded input or absent key")
		}
		if add.Validate() == nil && (key == (identity.IdempotencyKey{}) || !role.Valid() || orgVersion == 0 || orgVersion == ^uint64(0) || memberVersion == ^uint64(0) || len(value) > 128 || !utf8.ValidString(value)) {
			t.Fatal("add accepted invalid role, key, version or scope")
		}
		if remove.Validate() == nil && (orgVersion == 0 || orgVersion == ^uint64(0) || memberVersion == 0 || memberVersion == ^uint64(0) || len(value) > 128 || !utf8.ValidString(value)) {
			t.Fatal("remove accepted invalid version or scope")
		}
		if recovery.Validate() == nil && (binding.TenantID != auth.TenantID || binding.OperationID != string(organization.Create) && binding.OperationID != string(organization.AddMember) && binding.OperationID != string(organization.RemoveMember)) {
			t.Fatal("recovery accepted foreign scope or unselected operation")
		}
	})
}
