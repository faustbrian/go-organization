//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	organization "github.com/faustbrian/go-organization"
)

func TestOrganizationListFacadePreservesCurrentSelfPaging(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	for _, id := range []string{"c", "a", "b"} {
		createListedOrganization(t, f, tenant, id, true)
	}
	createListedOrganization(t, f, tenant, "not-mine", false)
	createListedOrganization(t, f, "org-test-scope", "foreign", true)
	policy := &organizationListPolicy{deny: "b"}
	// Reuse the existing native read-facade constructor with a failing ID
	// generator. A listing has no organization-allocation or keyed workflow.
	facade := slugNativeOperationService(t, listPolicyService(t, f, policy))
	request := organization.ListOrganizationsRequest{Authentication: f.auth(tenant, "member"), Limit: 1, CorrelationID: "list-facade"}
	first, err := facade.ListOrganizations(f.ctx, request)
	if err != nil || len(first.Organizations) != 1 || first.Organizations[0].ID != "a" || first.NextCursor == "" {
		t.Fatal("facade did not preserve the first visible self page", err)
	}
	request.Cursor = first.NextCursor
	last, err := facade.ListOrganizations(f.ctx, request)
	if err != nil || len(last.Organizations) != 1 || last.Organizations[0].ID != "c" || last.NextCursor != "" {
		t.Fatal("facade did not preserve filtered continuation/end", err)
	}
	for _, authentication := range []organization.Authentication{f.auth("org-test-scope", "member"), f.auth(tenant, "owner")} {
		foreign := request
		foreign.Authentication = authentication
		if result, err := facade.ListOrganizations(f.ctx, foreign); !errors.Is(err, organization.ErrInvalidInput) || len(result.Organizations) != 0 || result.NextCursor != "" {
			t.Fatal("facade continuation crossed authenticated scope", err)
		}
	}
	mismatch := request
	mismatch.Authentication.TenantID = "org-test-scope"
	if result, err := facade.ListOrganizations(f.ctx, mismatch); !errors.Is(err, organization.ErrForbidden) || len(result.Organizations) != 0 {
		t.Fatal("facade accepted a bearer under another tenant", err)
	}
	request.Cursor = ""
	request.Limit = 200
	request.Authentication = f.auth(tenant, "outsider")
	if result, err := facade.ListOrganizations(f.ctx, request); err != nil || result.Organizations == nil || len(result.Organizations) != 0 || result.NextCursor != "" {
		t.Fatal("facade invented membership or continuation for an empty self list", err)
	}
	request.Authentication = f.auth(tenant, "member")
	leave, err := f.service.PrepareLeaveMember(f.ctx, organization.LeaveRequest{Authentication: request.Authentication, CommandID: commandID(t), OrganizationID: "a", OrganizationVersion: 2, CorrelationID: "list-facade"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, leave)
	if result, err := facade.ListOrganizations(f.ctx, request); err != nil || len(result.Organizations) != 1 || result.Organizations[0].ID != "c" {
		t.Fatal("facade retained removed membership", err)
	}
	readmit, err := f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: "a", OrganizationVersion: 3, UserID: "member", MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "list-facade"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, readmit)
	if result, err := facade.ListOrganizations(f.ctx, request); err != nil || len(result.Organizations) != 2 || result.Organizations[0].ID != "a" || result.Organizations[0].Version != 4 {
		t.Fatal("facade did not observe current readmission", err)
	}
	policy.deny = "a"
	if result, err := facade.ListOrganizations(f.ctx, request); err != nil || len(result.Organizations) != 2 || result.Organizations[0].ID != "b" {
		t.Fatal("facade retained an earlier policy filter", err)
	}
	for _, limit := range []uint32{0, 201} {
		invalid := request
		invalid.Limit = limit
		if result, err := facade.ListOrganizations(f.ctx, invalid); !errors.Is(err, organization.ErrInvalidInput) || len(result.Organizations) != 0 {
			t.Fatal("facade invented a default or accepted an excessive limit", err)
		}
	}
	request.Cursor = organization.OrganizationCursor(strings.Repeat("a", 513))
	if result, err := facade.ListOrganizations(f.ctx, request); !errors.Is(err, organization.ErrInvalidInput) || len(result.Organizations) != 0 {
		t.Fatal("facade accepted an oversized continuation", err)
	}
}

func TestOrganizationListFacadeWithholdsLateAuthorityWithdrawal(t *testing.T) {
	for _, variant := range []string{"session", "policy-error", "canceled"} {
		t.Run(variant, func(t *testing.T) {
			f := newOrgFixture(t)
			for _, id := range []string{"a", "b"} {
				createListedOrganization(t, f, "org-test-basic", id, true)
			}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			policy := &organizationListPolicy{}
			fired := false
			policy.callback = func(ctx context.Context, decision authorization.DecisionContext) error {
				if fired || decision.Request.Resource.ID != "b" {
					return nil
				}
				fired = true
				switch variant {
				case "session":
					_, err := f.pool.Raw().Exec(ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='member'`)
					return err
				case "policy-error":
					return errors.New("private current-policy diagnostic")
				case "canceled":
					cancel()
				}
				return nil
			}
			facade := slugNativeOperationService(t, listPolicyService(t, f, policy))
			result, err := facade.ListOrganizations(ctx, organization.ListOrganizationsRequest{Authentication: f.auth("org-test-basic", "member"), Limit: 1, CorrelationID: "list-facade"})
			want := organization.ErrForbidden
			if variant == "policy-error" {
				want = organization.ErrUnavailable
			}
			if variant == "canceled" {
				want = context.Canceled
			}
			if !fired || !errors.Is(err, want) || len(result.Organizations) != 0 || result.NextCursor != "" {
				t.Fatal("facade disclosed a partial page after withdrawal", err)
			}
		})
	}
}
