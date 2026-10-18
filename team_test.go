package organization_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func FuzzTeamCreateBoundary(f *testing.F) {
	for _, seed := range [][2]string{{"engineering", "Engineering"}, {"", "Team"}, {"team", ""}, {"team", strings.Repeat("x", 257)}, {strings.Repeat("x", 129), "Team"}, {"cross tenant", "Team"}, {"team", "\x00"}, {"team", string([]byte{0xff})}, {"Équipe", "Équipe"}, {"team", " Team"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, id, name string) {
		if len(id) > 1024 || len(name) > 1024 {
			return
		}
		s, a, _, owner, policy := policyFixture(t, organization.TeamConfig{Version: 1, MaximumTeams: 100, MaximumMembers: 100})
		command, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		c, e := s.PrepareCreateTeam(t.Context(), organization.CreateTeamRequest{Authentication: a, CommandID: command, OrganizationID: "org", OrganizationVersion: 7, TeamID: organization.ID(id), Name: name, CorrelationID: "team-fuzz"})
		valid := utf8.ValidString(id) && utf8.ValidString(name) && len(id) > 0 && len(id) <= 128 && len(name) > 0 && len(name) <= 256 && strings.TrimSpace(name) == name
		for _, r := range id {
			if r <= 32 || r == 127 {
				valid = false
			}
		}
		for _, r := range name {
			if r < 32 || r == 127 {
				valid = false
			}
		}
		if !valid {
			if !errors.Is(e, organization.ErrInvalidInput) || c != (organization.Command{}) || owner.reads != 0 || policy.calls != 0 {
				t.Fatal("hostile input reached authenticated policy or storage")
			}
			return
		}
		x, projection := c.Input()
		if e != nil || projection != nil || x.Team.ID != organization.ID(id) || x.Team.Name != name || x.Binding.SchemaID != "organization-team" || x.Binding.ActorID != "actor" || x.Binding.UserID != "actor" || x.Organization.Version != 7 || owner.writes != 0 {
			t.Fatal("valid team preparation lost bounds, actor or schema", e)
		}
	})
}
