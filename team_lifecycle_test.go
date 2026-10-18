package organization_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestTeamConfigLegacyJSON(t *testing.T) {
	wire, e := json.Marshal(organization.TeamConfig{Version: 1, MaximumTeams: 100, MaximumMembers: 100})
	if e != nil || string(wire) != `{"Version":1,"MaximumTeams":100,"MaximumMembers":100}` {
		t.Fatal("omitted lifecycle changed historical team config bytes", e)
	}
}

func FuzzTeamLifecycleName(f *testing.F) {
	for _, name := range []string{"Platform", "Engineering", "", " New ", "\x00", string([]byte{0xff}), strings.Repeat("x", 256), strings.Repeat("x", 257), "Équipe"} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 1024 {
			return
		}
		s, a, _, owner, policy := policyFixture(t, organization.TeamConfig{Version: 1, MaximumTeams: 100, MaximumMembers: 100, LifecycleVersion: 1})
		owner.view.Team = organization.Team{ID: "engineering", OrganizationID: "org", TenantID: "tenant-a", Name: "Engineering", Version: 2}
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		command, e := s.PrepareUpdateTeam(t.Context(), organization.UpdateTeamRequest{Authentication: a, CommandID: id, OrganizationID: "org", OrganizationVersion: 7, TeamID: "engineering", TeamVersion: 2, Name: name, CorrelationID: "team-name-fuzz"})
		valid := len(name) > 0 && len(name) <= 256 && utf8.ValidString(name) && strings.TrimSpace(name) == name
		for _, r := range name {
			if r < 32 || r == 127 {
				valid = false
			}
		}
		if !valid {
			if !errors.Is(e, organization.ErrInvalidInput) || owner.reads != 0 || policy.calls != 0 {
				t.Fatal("hostile lifecycle name reached storage/policy")
			}
			return
		}
		if name == "Engineering" {
			if !errors.Is(e, organization.ErrConflict) {
				t.Fatal("noop escaped conflict", e)
			}
			return
		}
		x, projection := command.Input()
		if e != nil || projection != nil || x.Team.Name != name || x.Team.Version != 2 || x.Organization.Version != 7 || owner.writes != 0 {
			t.Fatal("bounded lifecycle name changed or wrote state", e)
		}
	})
}

func TestTeamLifecyclePreparation(t *testing.T) {
	s, a, _, owner, _ := policyFixture(t, organization.TeamConfig{Version: 1, MaximumTeams: 100, MaximumMembers: 100, LifecycleVersion: 1})
	owner.view.Team = organization.Team{ID: "engineering", OrganizationID: "org", TenantID: "tenant-a", Name: "Engineering", Version: 2}
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	r := organization.UpdateTeamRequest{Authentication: a, CommandID: id, OrganizationID: "org", TeamID: "engineering", OrganizationVersion: 7, TeamVersion: 2, Name: "Platform", CorrelationID: "team-update"}
	command, e := s.PrepareUpdateTeam(t.Context(), r)
	if e != nil {
		t.Fatal(e)
	}
	x, e := command.Input()
	if e != nil || x.Team.Name != "Platform" || x.Team.Version != 2 || x.Organization.Version != 7 || x.Operation != organization.UpdateTeam || x.Binding.UserID != "actor" {
		t.Fatal("team update lost exact actor/version/name", e)
	}
	work := outcomeOwner(func(c organization.Command) (organization.StoreResult, error) {
		got, e := owner.Execute(t.Context(), c)
		got.Receipt.AuditEventID = "team-audit"
		return got, e
	})
	if got, e := s.Execute(t.Context(), command, work); e != nil || got.Receipt.Feature.AfterVersion != 8 {
		t.Fatal("team update handoff", e)
	}
	r.TeamVersion = 1
	if _, e = s.PrepareUpdateTeam(t.Context(), r); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("stale team admitted", e)
	}
	d := organization.DeleteTeamRequest{Authentication: a, CommandID: id, OrganizationID: "org", TeamID: "engineering", OrganizationVersion: 7, TeamVersion: 2, CorrelationID: "team-delete"}
	command, e = s.PrepareDeleteTeam(t.Context(), d)
	if e != nil {
		t.Fatal(e)
	}
	x, e = command.Input()
	if e != nil || x.Operation != organization.DeleteTeam || x.Team.Name != "Engineering" {
		t.Fatal("delete did not retain exact original team", e)
	}
	view, e := s.GetTeam(t.Context(), organization.TeamReadRequest{Authentication: a, OrganizationID: "org", TeamID: "engineering", CorrelationID: "team-get"})
	if e != nil || view.Team.ID != "engineering" {
		t.Fatal("exact team get", e)
	}
}
