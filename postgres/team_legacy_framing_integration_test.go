//go:build integration

package postgres_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// This is literal published membership-profile framing, not a newly generated
// expected fixture. The profile has no AEAD preparation/config envelope: the
// native session contributor owns bearer custody and these typed scalar fields
// enter the existing coordinator's canonical keyed fingerprint.
func TestLegacyTeamCommandFramingRemainsExact(t *testing.T) {
	f := teamFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	repository, e := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	core, e := organization.NewService(f.sessions, repository, f.configuration.Authorization, f.configuration.Core)
	if e != nil {
		t.Fatal(e)
	}
	command, e := core.PrepareCreateTeam(f.ctx, organization.CreateTeamRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 1, TeamID: "engineering", Name: "Engineering", CorrelationID: "legacy-frame"})
	if e != nil {
		t.Fatal(e)
	}
	native, e := f.participant.MapCommand(command)
	if e != nil {
		t.Fatal(e)
	}
	spec, ok := native.Feature()
	if !ok {
		t.Fatal("legacy feature schema lost")
	}
	wire, e := json.Marshal(spec.Operation)
	if e != nil || string(wire) != `{"Owner":"organization","OperationID":"identity.organization.team.create","SchemaID":"organization-team","SchemaVersion":1,"RecordRequirement":2}` {
		t.Fatal("legacy feature descriptor bytes changed", e)
	}
	var names []string
	for _, field := range spec.Fields {
		if strings.HasPrefix(field.Name, "organization.") {
			names = append(names, field.Name)
		}
	}
	const original = `organization.actor-authorization,organization.actor-role,organization.actor-version,organization.maximum-members,organization.maximum-per-tenant,organization.maximum-per-user,organization.maximum-team-members,organization.maximum-teams,organization.member-authorization,organization.member-role,organization.member-version,organization.name,organization.role,organization.session-until,organization.slug,organization.target-status,organization.target-version,organization.team-id,organization.team-member-organization-version,organization.team-member-version,organization.team-name,organization.team-policy-version,organization.team-version,organization.version`
	if strings.Join(names, ",") != original {
		t.Fatal("lifecycle extended historical feature field framing")
	}
	p, e := f.service.PrepareCreateTeam(f.ctx, organization.CreateTeamRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 1, TeamID: "engineering", Name: "Engineering", CorrelationID: "legacy-recovery"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, p)
	handle, e := p.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	safe, e := json.Marshal(handle)
	if e != nil || strings.Contains(string(safe), "LifecycleVersion") {
		t.Fatal("recovery handle acquired lifecycle configuration", e)
	}
	var restored organizationpg.Recovery
	if json.Unmarshal(safe, &restored) != nil || restored != handle {
		t.Fatal("legacy recovery binding changed")
	}
	result, e := f.service.Recover(f.ctx, f.auth(tenant, "owner"), restored)
	if e != nil || result.Receipt.Binding != handle.Binding {
		t.Fatal("historical membership command did not recover", e)
	}
}
