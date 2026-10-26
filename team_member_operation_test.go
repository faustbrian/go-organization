package organization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func teamMemberOperationRequest(t testing.TB) organization.AddTeamMemberOperationRequest {
	t.Helper()
	r := teamCreateOperationRequest(t)
	return organization.AddTeamMemberOperationRequest{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, OrganizationID: "org", TeamID: "team", UserID: "member", OrganizationVersion: 4, TeamVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "team-member"}
}

func teamMemberRemoval(r organization.AddTeamMemberOperationRequest) organization.RemoveTeamMemberOperationRequest {
	return organization.RemoveTeamMemberOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, TeamID: r.TeamID, UserID: r.UserID, OrganizationVersion: r.OrganizationVersion, TeamVersion: r.TeamVersion, OrganizationMemberVersion: r.OrganizationMemberVersion, MembershipVersion: r.MembershipVersion, CorrelationID: r.CorrelationID}
}

func TestTeamMemberOperationExactBoundedIntentAndCustody(t *testing.T) {
	r := teamMemberOperationRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(teamMemberRemoval(r).Validate(), organization.ErrInvalidInput) {
		t.Fatal("zero removal binding accepted")
	}
	r.MembershipVersion = 1
	if err := teamMemberRemoval(r).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*organization.AddTeamMemberOperationRequest){
		"org":    func(r *organization.AddTeamMemberOperationRequest) { r.OrganizationID = "" },
		"team":   func(r *organization.AddTeamMemberOperationRequest) { r.TeamID = "bad team" },
		"target": func(r *organization.AddTeamMemberOperationRequest) { r.UserID = "member\n" },
		"long target": func(r *organization.AddTeamMemberOperationRequest) {
			r.UserID = identity.UserID(strings.Repeat("a", 129))
		},
		"utf8":             func(r *organization.AddTeamMemberOperationRequest) { r.TeamID = "\xff" },
		"org epoch":        func(r *organization.AddTeamMemberOperationRequest) { r.OrganizationVersion = 0 },
		"org overflow":     func(r *organization.AddTeamMemberOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"team epoch":       func(r *organization.AddTeamMemberOperationRequest) { r.TeamVersion = 0 },
		"team overflow":    func(r *organization.AddTeamMemberOperationRequest) { r.TeamVersion = ^uint64(0) },
		"org admission":    func(r *organization.AddTeamMemberOperationRequest) { r.OrganizationMemberVersion = 0 },
		"binding overflow": func(r *organization.AddTeamMemberOperationRequest) { r.MembershipVersion = ^uint64(0) },
		"correlation":      func(r *organization.AddTeamMemberOperationRequest) { r.CorrelationID = "" },
		"tenant":           func(r *organization.AddTeamMemberOperationRequest) { r.Authentication.TenantID = "foreign tenant" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) || !errors.Is(teamMemberRemoval(bad).Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid team membership intent accepted")
			}
		})
	}
	bad := r
	bad.IdempotencyKey = identity.IdempotencyKey{}
	if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
		t.Fatal("missing admission key accepted")
	}
	maximum := r
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.TeamID = organization.ID(strings.Repeat("t", 128))
	maximum.UserID = identity.UserID(strings.Repeat("u", 128))
	maximum.OrganizationVersion = ^uint64(0) - 1
	maximum.TeamVersion = ^uint64(0) - 1
	maximum.OrganizationMemberVersion = ^uint64(0)
	maximum.MembershipVersion = ^uint64(0) - 1
	if err := maximum.Validate(); err != nil {
		t.Fatal("existing native bounds changed", err)
	}
	for _, item := range []struct {
		value any
		label string
	}{{r, "AddTeamMemberOperationRequest"}, {teamMemberRemoval(r), "RemoveTeamMemberOperationRequest"}} {
		if _, err := json.Marshal(item.value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("credential/key exported")
		}
		if _, err := item.value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("custody text exported")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if got := fmt.Sprintf(format, item.value); got != "organization."+item.label+"(redacted)" {
				t.Fatal("diagnostics exposed custody")
			}
		}
	}
}

func TestTeamMemberOperationRecoveryRetainsExactTarget(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []organization.Operation{organization.AddTeamMember, organization.RemoveTeamMember} {
		d := op.Descriptor()
		r := organization.OperationRecoveryRequest{Authentication: teamCreateOperationRequest(t).Authentication, Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "member", ActorID: "owner", ActorKind: authorization.SubjectUser, OperationID: d.OperationID, RecordID: "org", SchemaID: d.SchemaID, SchemaVersion: d.SchemaVersion, PolicyID: "organization", PolicyVersion: 1, CorrelationID: "original-team-member"}}
		if err := r.Validate(); err != nil {
			t.Fatalf("exact team-member original recovery rejected: %v", err)
		}
		for _, change := range []func(*organization.OperationRecoveryRequest){
			func(r *organization.OperationRecoveryRequest) { r.Authentication.TenantID = "foreign" },
			func(r *organization.OperationRecoveryRequest) {
				r.Binding.ActorKind = authorization.SubjectServiceAccount
			},
			func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaID = "organization" },
		} {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("foreign recovery syntax accepted")
			}
		}
	}
}

func FuzzTeamMemberOperationValidation(f *testing.F) {
	for _, seed := range []string{"member", "", "bad team", "\xff", "name\n", strings.Repeat("x", 128), strings.Repeat("x", 129)} {
		f.Add(seed, uint64(1), uint8(0))
	}
	f.Fuzz(func(t *testing.T, value string, version uint64, mode uint8) {
		if len(value) > 4096 {
			return
		}
		r := teamMemberOperationRequest(t)
		r.MembershipVersion = version
		switch mode % 3 {
		case 0:
			r.UserID = identity.UserID(value)
		case 1:
			r.TeamID = organization.ID(value)
		case 2:
			r.OrganizationID = organization.ID(value)
		}
		addErr := r.Validate()
		removeErr := teamMemberRemoval(r).Validate()
		if addErr != nil && !errors.Is(addErr, organization.ErrInvalidInput) || removeErr != nil && !errors.Is(removeErr, organization.ErrInvalidInput) || addErr != nil && removeErr == nil || version == 0 && removeErr == nil || version == ^uint64(0) && addErr == nil {
			t.Fatal("invalid exact-binding validation outcome")
		}
	})
}
