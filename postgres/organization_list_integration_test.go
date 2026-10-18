//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func createListedOrganization(t *testing.T, f *orgFixture, tenant, id string, admit bool) {
	t.Helper()
	p, err := f.service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), ID: organization.ID(id), Slug: id, Name: "Organization " + id, CorrelationID: "organization-list"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, p)
	if admit {
		p, err = f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: organization.ID(id), UserID: "member", OrganizationVersion: 1, Role: organization.RoleMember, CorrelationID: "organization-list"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		committedTeam(t, f, p)
	}
}

type organizationListPolicy struct {
	deny     organization.ID
	callback func(context.Context, authorization.DecisionContext) error
}

func (p *organizationListPolicy) Decide(ctx context.Context, request authorization.DecisionContext) (authorization.Decision, error) {
	if request.Request.Action == authorization.Action(organization.ListOrganizations) {
		if p.callback != nil {
			if err := p.callback(ctx, request); err != nil {
				return authorization.Decision{}, err
			}
		}
		if organization.ID(request.Request.Resource.ID) == p.deny {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
		}
	}
	return (fixturePolicy{}).Decide(ctx, request)
}

func listPolicyService(t *testing.T, f *orgFixture, policy authorization.Service) *organizationpg.Service {
	t.Helper()
	config := f.configuration
	config.Authorization = policy
	s, err := organizationpg.NewService(f.participant, config)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOrganizationListCurrentSubjectStableVisiblePages(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	for _, id := range []string{"c", "a", "b"} {
		createListedOrganization(t, f, tenant, id, true)
	}
	createListedOrganization(t, f, tenant, "not-mine", false)
	createListedOrganization(t, f, "org-test-scope", "foreign", true)
	policy := &organizationListPolicy{deny: "b"}
	s := listPolicyService(t, f, policy)
	r := organization.ListOrganizationsRequest{Authentication: f.auth(tenant, "member"), Limit: 1, CorrelationID: "organization-list"}
	first, err := s.ListOrganizations(f.ctx, r)
	if err != nil || len(first.Organizations) != 1 || first.Organizations[0].ID != "a" || first.NextCursor == "" {
		t.Fatal("first owned visible organization page", err)
	}
	r.Cursor = first.NextCursor
	last, err := s.ListOrganizations(f.ctx, r)
	if err != nil || len(last.Organizations) != 1 || last.Organizations[0].ID != "c" || last.NextCursor != "" {
		t.Fatal("denied middle org blocked next visible page", err)
	}
	foreign := r
	foreign.Authentication = f.auth("org-test-scope", "member")
	if _, err = s.ListOrganizations(f.ctx, foreign); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("cursor crossed tenant scope", err)
	}
	foreign.Authentication = f.auth(tenant, "owner")
	if _, err = s.ListOrganizations(f.ctx, foreign); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("cursor crossed actor scope", err)
	}
	r.Cursor = ""
	r.Limit = 201
	if _, err = s.ListOrganizations(f.ctx, r); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("overlarge page admitted", err)
	}
	r.Limit = 200
	page, err := s.ListOrganizations(f.ctx, r)
	if err != nil || len(page.Organizations) != 2 {
		t.Fatal("bounded maximum page rejected", err)
	}
	leave, err := f.service.PrepareLeaveMember(f.ctx, organization.LeaveRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: "a", OrganizationVersion: 2, CorrelationID: "organization-list"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, leave)
	page, err = s.ListOrganizations(f.ctx, r)
	if err != nil || len(page.Organizations) != 1 || page.Organizations[0].ID != "c" {
		t.Fatal("removed membership was listed", err)
	}
	readmit, err := f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: "a", OrganizationVersion: 3, UserID: "member", MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "organization-list"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, readmit)
	page, err = s.ListOrganizations(f.ctx, r)
	if err != nil || len(page.Organizations) != 2 || page.Organizations[0].ID != "a" || page.Organizations[0].Version != 4 {
		t.Fatal("current readmission not listed", err)
	}
	// Test only persisted inactive-state filtering, not an unselected lifecycle.
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state='archived',version=version+1 WHERE tenant_id=$1 AND organization_id='a'`, tenant); err != nil {
		t.Fatal(err)
	}
	page, err = s.ListOrganizations(f.ctx, r)
	if err != nil || len(page.Organizations) != 1 || page.Organizations[0].ID != "c" {
		t.Fatal("inactive organization was listed", err)
	}
}

func TestOrganizationListRevalidatesAfterExternalPolicy(t *testing.T) {
	f := newOrgFixture(t)
	variants := []string{"session", "member", "epoch", "scoped-authority", "late-policy", "canceled"}
	for i, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			tenant := []string{"org-test-basic", "org-test-race", "org-test-scope", "org-test-target", "org-test-rollback", "org-test-unknown"}[i]
			createListedOrganization(t, f, tenant, "a", true)
			createListedOrganization(t, f, tenant, "b", true)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			policy := &organizationListPolicy{}
			fired := false
			policy.callback = func(ctx context.Context, c authorization.DecisionContext) error {
				if fired || c.Request.Resource.ID != "b" {
					return nil
				}
				fired = true
				var err error
				switch variant {
				case "session":
					_, err = f.pool.Raw().Exec(ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='member'`, tenant)
				case "member":
					_, err = f.pool.Raw().Exec(ctx, `UPDATE organization.memberships SET state='removed',version=version+1 WHERE tenant_id=$1 AND organization_id='a' AND user_id='member'`, tenant)
				case "epoch":
					_, err = f.pool.Raw().Exec(ctx, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1 AND organization_id='a'`, tenant)
				case "scoped-authority":
					scope, e := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), "a", "member")
					if e != nil {
						return e
					}
					_, err = authority.AdvanceAuthority(ctx, f.pool.Raw(), scope, 1, time.Second)
				case "late-policy":
					policy.deny = "a"
				case "canceled":
					cancel()
				}
				return err
			}
			s := listPolicyService(t, f, policy)
			got, err := s.ListOrganizations(ctx, organization.ListOrganizationsRequest{Authentication: f.auth(tenant, "member"), Limit: 1, CorrelationID: "organization-list"})
			want := organization.ErrForbidden
			if variant == "canceled" {
				want = context.Canceled
			}
			if !fired || !errors.Is(err, want) || len(got.Organizations) != 0 || got.NextCursor != "" {
				t.Fatal("late authority withdrawal disclosed list", err)
			}
		})
	}
}

func TestOrganizationListNativeBoundsAndAuthorityErrors(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	for _, id := range []string{"c", "a", "b"} {
		createListedOrganization(t, f, tenant, id, true)
	}
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	query := organization.OrganizationListQuery{TenantID: identity.TenantID(tenant), ActorID: "member", MaximumRows: 1}
	entries, err := repository.ReadOrganizations(f.ctx, query)
	if err != nil || len(entries) != 2 || entries[0].Organization.ID != "a" || entries[1].Organization.ID != "b" {
		t.Fatal("native bounded C-order/overflow detector failed", err)
	}
	query.After = "a"
	entries, err = repository.ReadOrganizations(f.ctx, query)
	if err != nil || len(entries) != 2 || entries[0].Organization.ID != "b" || entries[1].Organization.ID != "c" {
		t.Fatal("native exclusive keyset changed order", err)
	}
	for _, maximum := range []uint32{0, 1001, ^uint32(0)} {
		query.MaximumRows = maximum
		if _, err = repository.ReadOrganizations(f.ctx, query); !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("native overlarge scan admitted", err)
		}
	}
	request := organization.ListOrganizationsRequest{Authentication: f.auth(tenant, "member"), Limit: 2, CorrelationID: "organization-list"}
	policy := &organizationListPolicy{callback: func(context.Context, authorization.DecisionContext) error {
		return errors.New("private authority diagnostic")
	}}
	if got, err := listPolicyService(t, f, policy).ListOrganizations(f.ctx, request); !errors.Is(err, organization.ErrUnavailable) || len(got.Organizations) != 0 || got.NextCursor != "" {
		t.Fatal("policy outage disclosed organization metadata", err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if got, err := f.service.ListOrganizations(ctx, request); !errors.Is(err, context.Canceled) || len(got.Organizations) != 0 {
		t.Fatal("canceled native list disclosed organizations", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE organization.memberships RENAME TO unavailable_memberships`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := f.pool.Raw().Exec(cleanup, `ALTER TABLE organization.unavailable_memberships RENAME TO memberships`); err != nil {
			t.Error("owned list fault restoration failed", err)
		}
	}()
	if got, err := f.service.ListOrganizations(f.ctx, request); !errors.Is(err, organization.ErrUnavailable) || len(got.Organizations) != 0 || got.NextCursor != "" {
		t.Fatal("native SQL outage disclosed organization metadata", err)
	}
}
