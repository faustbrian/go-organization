//go:build integration

package postgres_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOrganizationPostgresQuotaDenial(t *testing.T) {
	f := newOrgFixture(t)
	f.composeWithTenantLimit(t, 1)
	tenant := "org-test-basic"
	f.create(t, tenant)
	id := organization.ID("01ARZ3NDEKTSV4RRFFQ69G5FAW")
	p, e := f.service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), ID: id, Slug: "over-quota", Name: "Over quota", CorrelationID: "quota-denied"}, "127.0.0.1")
	if e != nil {
		t.Fatal("quota must be checked inside protected execution", e)
	}
	recovery, e := p.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	r, e := f.service.Execute(f.ctx, p)
	if !errors.Is(e, organization.ErrForbidden) || r.Receipt.Outcome != identity.CommitOutcomeNotCommitted || r.Receipt.Binding != recovery.Binding {
		t.Error("protected quota rejection must be a terminal authorization denial", r.Receipt.Outcome, e)
	}
	commandID, e := base64.RawURLEncoding.DecodeString(string(recovery.Binding.CommandID))
	if e != nil {
		t.Fatal(e)
	}
	var state, class string
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT state,terminal_class FROM identity.commands WHERE tenant_id=$1 AND command_id=$2`, tenant, commandID).Scan(&state, &class); e != nil || state != "aborted" || class != "denied" {
		t.Error("quota journal classification must be denied, not dependency failure", state, class, e)
	}
	var audits, denied int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE r.outcome=$3 AND convert_from(r.canonical_record,'UTF8')::jsonb->>'reason_code'='not_authorized') FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.tenant_id=$1 AND b.command_id=$2`, tenant, commandID, int16(audit.OutcomeDenied)).Scan(&audits, &denied); e != nil || audits != 1 || denied != 1 {
		t.Error("quota rejection must retain one denied audit", audits, denied, e)
	}
	scope, e := organizationpg.OrganizationAuthorityScope(recovery.Binding.TenantID, id, recovery.Binding.UserID)
	if e != nil {
		t.Fatal(e)
	}
	var organizations, memberships, effects, authorities int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2),(SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2),(SELECT count(*) FROM organization.command_effects WHERE command_id=$3),(SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace=$4)`, tenant, string(id), string(recovery.Binding.CommandID), scope.PolicyNamespace).Scan(&organizations, &memberships, &effects, &authorities); e != nil || organizations != 0 || memberships != 0 || effects != 0 || authorities != 0 {
		t.Error("quota denial left domain or scoped authority effects", organizations, memberships, effects, authorities, e)
	}
	r, e = f.service.Execute(f.ctx, p)
	if e != nil || r.Receipt.Outcome != identity.CommitOutcomeNotCommitted || r.Receipt.Binding != recovery.Binding {
		t.Error("quota replay changed retained terminal outcome", r.Receipt.Outcome, e)
	}
}
