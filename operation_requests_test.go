package organization_test

import (
	"encoding/base64"
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

func TestUpdateMemberOperationRecoveryRetainsOriginalBinding(t *testing.T) {
	r := organization.OperationRecoveryRequest{
		Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		Binding: identity.CommandBinding{
			CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", TenantID: "tenant", UserID: "member", ActorID: "owner", ActorKind: authorization.SubjectUser,
			OperationID: string(organization.UpdateMember), RecordID: "org", PolicyID: "organization", PolicyVersion: 1,
			SchemaID: "organization-membership", SchemaVersion: 1, CorrelationID: "update-member",
		},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("original member-role outcome recovery rejected: %v", err)
	}
	for name, change := range map[string]func(*organization.OperationRecoveryRequest){
		"foreign tenant":  func(r *organization.OperationRecoveryRequest) { r.Authentication.TenantID = "other" },
		"missing command": func(r *organization.OperationRecoveryRequest) { r.Binding.CommandID = "" },
		"wrong schema":    func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaID = "organization" },
		"hard deletion remains separate": func(r *organization.OperationRecoveryRequest) {
			r.Binding.OperationID = "identity.organization.delete"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid original recovery binding accepted")
			}
		})
	}
}

func TestUpdateMemberOperationRequestRetainsExactStaticRoleCustody(t *testing.T) {
	key, err := identity.NewIdempotencyKey([]byte("original-member-role-update"))
	if err != nil {
		t.Fatal(err)
	}
	r := organization.UpdateMemberOperationRequest{
		Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		IdempotencyKey: key, OrganizationID: "organization", UserID: "member", Role: organization.RoleAdministrator,
		OrganizationVersion: 1, MemberVersion: 1, CorrelationID: "update-member",
	}
	for _, role := range []organization.Role{organization.RoleMember, organization.RoleAdministrator, organization.RoleOwner} {
		valid := r
		valid.Role = role
		if err := valid.Validate(); err != nil {
			t.Fatal("static-role syntax rejected before native admission", err)
		}
	}
	maximum := r
	maximum.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 128))
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.UserID = identity.UserID(strings.Repeat("u", 128))
	maximum.CorrelationID = strings.Repeat("c", 128)
	maximum.OrganizationVersion, maximum.MemberVersion = ^uint64(0)-1, ^uint64(0)-1
	if err := maximum.Validate(); err != nil {
		t.Fatal("maximum incrementable versions or IDs rejected", err)
	}
	for name, change := range map[string]func(*organization.UpdateMemberOperationRequest){
		"missing key": func(r *organization.UpdateMemberOperationRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"invalid bearer": func(r *organization.UpdateMemberOperationRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
		"missing tenant": func(r *organization.UpdateMemberOperationRequest) { r.Authentication.TenantID = "" },
		"long tenant": func(r *organization.UpdateMemberOperationRequest) {
			r.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 129))
		},
		"missing organization": func(r *organization.UpdateMemberOperationRequest) { r.OrganizationID = "" },
		"long organization": func(r *organization.UpdateMemberOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"missing member": func(r *organization.UpdateMemberOperationRequest) { r.UserID = "" },
		"long member": func(r *organization.UpdateMemberOperationRequest) {
			r.UserID = identity.UserID(strings.Repeat("u", 129))
		},
		"control member":                func(r *organization.UpdateMemberOperationRequest) { r.UserID = "member\n" },
		"invalid unicode":               func(r *organization.UpdateMemberOperationRequest) { r.OrganizationID = "\xff" },
		"unknown role":                  func(r *organization.UpdateMemberOperationRequest) { r.Role = "dynamic-role" },
		"missing organization version":  func(r *organization.UpdateMemberOperationRequest) { r.OrganizationVersion = 0 },
		"overflow organization version": func(r *organization.UpdateMemberOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"missing member version":        func(r *organization.UpdateMemberOperationRequest) { r.MemberVersion = 0 },
		"overflow member version":       func(r *organization.UpdateMemberOperationRequest) { r.MemberVersion = ^uint64(0) },
		"missing correlation":           func(r *organization.UpdateMemberOperationRequest) { r.CorrelationID = "" },
		"untrimmed correlation":         func(r *organization.UpdateMemberOperationRequest) { r.CorrelationID = " update" },
		"long correlation":              func(r *organization.UpdateMemberOperationRequest) { r.CorrelationID = strings.Repeat("c", 129) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid original member-role request accepted")
			}
		})
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
		organization.UpdateOperationRequest{Authentication: auth, IdempotencyKey: key, Name: "private-name"},
		organization.AddMemberOperationRequest{Authentication: auth, IdempotencyKey: key},
		organization.UpdateMemberOperationRequest{Authentication: auth, IdempotencyKey: key, UserID: "private-name"},
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

func TestUpdateOperationRequestRetainsKeyedMetadataCustody(t *testing.T) {
	key, err := identity.NewIdempotencyKey([]byte("original-organization-update"))
	if err != nil {
		t.Fatal(err)
	}
	r := organization.UpdateOperationRequest{
		Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		IdempotencyKey: key, OrganizationID: "organization", OrganizationVersion: 1,
		Name: "New name", Slug: "new-slug", CorrelationID: "update",
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	maximum := r
	maximum.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 128))
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.OrganizationVersion = ^uint64(0) - 1
	maximum.Name, maximum.Slug, maximum.CorrelationID = strings.Repeat("n", 256), strings.Repeat("s", 63), strings.Repeat("c", 128)
	if err := maximum.Validate(); err != nil {
		t.Fatalf("valid maximum rejected: %v", err)
	}
	for name, change := range map[string]func(*organization.UpdateOperationRequest){
		"missing key":          func(r *organization.UpdateOperationRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"missing organization": func(r *organization.UpdateOperationRequest) { r.OrganizationID = "" },
		"long organization": func(r *organization.UpdateOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"organization whitespace": func(r *organization.UpdateOperationRequest) { r.OrganizationID = "other organization" },
		"missing version":         func(r *organization.UpdateOperationRequest) { r.OrganizationVersion = 0 },
		"overflow version":        func(r *organization.UpdateOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"missing name":            func(r *organization.UpdateOperationRequest) { r.Name = "" },
		"long name":               func(r *organization.UpdateOperationRequest) { r.Name = strings.Repeat("n", 257) },
		"untrimmed name":          func(r *organization.UpdateOperationRequest) { r.Name = " name" },
		"control name":            func(r *organization.UpdateOperationRequest) { r.Name = "name\nsecret" },
		"invalid utf8":            func(r *organization.UpdateOperationRequest) { r.Name = "\xff" },
		"missing slug":            func(r *organization.UpdateOperationRequest) { r.Slug = "" },
		"long slug":               func(r *organization.UpdateOperationRequest) { r.Slug = strings.Repeat("s", 64) },
		"uppercase slug":          func(r *organization.UpdateOperationRequest) { r.Slug = "New-Slug" },
		"leading dash":            func(r *organization.UpdateOperationRequest) { r.Slug = "-slug" },
		"trailing dash":           func(r *organization.UpdateOperationRequest) { r.Slug = "slug-" },
		"invalid bearer": func(r *organization.UpdateOperationRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
		"missing tenant": func(r *organization.UpdateOperationRequest) { r.Authentication.TenantID = "" },
		"long tenant": func(r *organization.UpdateOperationRequest) {
			r.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 129))
		},
		"missing correlation": func(r *organization.UpdateOperationRequest) { r.CorrelationID = "" },
		"long correlation":    func(r *organization.UpdateOperationRequest) { r.CorrelationID = strings.Repeat("c", 129) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid keyed metadata request accepted")
			}
		})
	}
}

func TestUpdateOperationRecoveryRetainsOriginalBinding(t *testing.T) {
	r := organization.OperationRecoveryRequest{
		Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		Binding:        identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", TenantID: "tenant", UserID: "owner", ActorID: "owner", ActorKind: authorization.SubjectUser, OperationID: string(organization.Update), RecordID: "org", PolicyID: "organizations", PolicyVersion: 1, SchemaID: "organization-membership", SchemaVersion: 1, CorrelationID: "update"},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("original metadata recovery rejected: %v", err)
	}
	r.Authentication.TenantID = "other"
	if !errors.Is(r.Validate(), organization.ErrInvalidInput) {
		t.Fatal("foreign metadata recovery accepted")
	}
}

func FuzzUpdateOperationRequestValidation(f *testing.F) {
	for _, value := range []string{"name", "", "\x00", "\xff", " name", "NAME", "slug-", strings.Repeat("a", 63), strings.Repeat("a", 64), strings.Repeat("a", 128), strings.Repeat("a", 129), strings.Repeat("a", 256), strings.Repeat("a", 257)} {
		f.Add(value, uint64(1), uint8(0))
	}
	f.Add("name", ^uint64(0), uint8(63))
	f.Fuzz(func(t *testing.T, value string, version uint64, mode uint8) {
		if len(value) > 4096 {
			return
		}
		key, err := identity.NewIdempotencyKey([]byte("synthetic-fuzz-update"))
		if err != nil {
			t.Fatal("fuzz key construction failed")
		}
		r := organization.UpdateOperationRequest{Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, IdempotencyKey: key, OrganizationID: "organization", OrganizationVersion: version, Name: value, Slug: "slug", CorrelationID: "update"}
		if mode&1 != 0 {
			r.Slug = value
		}
		if mode&2 != 0 {
			r.OrganizationID = organization.ID(value)
		}
		if mode&4 != 0 {
			r.CorrelationID = value
		}
		if mode&8 != 0 {
			r.Authentication.TenantID = identity.TenantID(value)
		}
		if mode&16 != 0 {
			r.Authentication.Bearer = authentication.NewBearerCredential(value)
		}
		if mode&32 != 0 {
			r.IdempotencyKey = identity.IdempotencyKey{}
		}
		err = r.Validate()
		if err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("unclassified validation error")
		}
		if err == nil && (r.IdempotencyKey == (identity.IdempotencyKey{}) || version == 0 || version == ^uint64(0) || len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\n\r\t\x7f")) {
			t.Fatal("accepted hostile metadata, missing key or invalid version")
		}
		if err == nil && ((mode&1 != 0 && len(value) > 63) || (mode&14 != 0 && len(value) > 128)) {
			t.Fatal("accepted oversized scope")
		}
	})
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
			r.Binding.OperationID = "identity.organization.delete"
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
		if recovery.Validate() == nil && (binding.TenantID != auth.TenantID || binding.OperationID != string(organization.Create) && binding.OperationID != string(organization.AddMember) && binding.OperationID != string(organization.UpdateMember) && binding.OperationID != string(organization.RemoveMember) && binding.OperationID != string(organization.Update)) {
			t.Fatal("recovery accepted foreign scope or unselected operation")
		}
	})
}

func FuzzUpdateMemberOperationRequestValidation(f *testing.F) {
	for _, value := range []string{"member", "owner", "administrator", "", "é", "\xff", "\x00", " member", "a b", strings.Repeat("x", 128), strings.Repeat("x", 129), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		for _, mode := range []uint8{0, 1, 2, 4, 8, 16, 32, 64} {
			f.Add(value, uint64(1), uint64(1), mode)
		}
	}
	f.Add("member", uint64(0), uint64(0), uint8(0))
	f.Add("member", ^uint64(0)-1, ^uint64(0)-1, uint8(0))
	f.Add("member", ^uint64(0), ^uint64(0), uint8(127))
	f.Fuzz(func(t *testing.T, value string, orgVersion, memberVersion uint64, mode uint8) {
		if len(value) > 4096 {
			return
		}
		key, err := identity.NewIdempotencyKey([]byte("synthetic-fuzz-member-update"))
		if err != nil {
			t.Fatal(err)
		}
		r := organization.UpdateMemberOperationRequest{Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, IdempotencyKey: key, OrganizationID: "organization", UserID: "member", Role: organization.RoleMember, OrganizationVersion: orgVersion, MemberVersion: memberVersion, CorrelationID: "update-member"}
		if mode&1 != 0 {
			r.Role = organization.Role(value)
		}
		if mode&2 != 0 {
			r.OrganizationID = organization.ID(value)
		}
		if mode&4 != 0 {
			r.UserID = identity.UserID(value)
		}
		if mode&8 != 0 {
			r.Authentication.TenantID = identity.TenantID(value)
		}
		if mode&16 != 0 {
			r.CorrelationID = value
		}
		if mode&32 != 0 {
			r.Authentication.Bearer = authentication.NewBearerCredential(value)
		}
		if mode&64 != 0 {
			r.IdempotencyKey = identity.IdempotencyKey{}
		}
		safe := func(s string) bool {
			return s != "" && len(s) <= 128 && utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 127 })
		}
		token, tokenErr := base64.RawURLEncoding.DecodeString(r.Authentication.Bearer.Token())
		valid := r.IdempotencyKey != (identity.IdempotencyKey{}) && safe(string(r.Authentication.TenantID)) && safe(string(r.OrganizationID)) && safe(string(r.UserID)) && safe(r.CorrelationID) && r.Role.Valid() && orgVersion > 0 && orgVersion < ^uint64(0) && memberVersion > 0 && memberVersion < ^uint64(0) && tokenErr == nil && len(token) >= 32 && len(token) <= 64 && base64.RawURLEncoding.EncodeToString(token) == r.Authentication.Bearer.Token()
		err = r.Validate()
		if (err == nil) != valid || err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("member-role validation disagrees with bounded syntax/custody contract")
		}
		if _, err := json.Marshal(r); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("member-role custody serialized")
		}
		if _, err := r.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("member-role custody serialized as text")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if fmt.Sprintf(format, r) != "organization.UpdateMemberOperationRequest(redacted)" {
				t.Fatal("member-role diagnostic exposed input")
			}
		}
	})
}
