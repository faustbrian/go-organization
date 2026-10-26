//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func slugNativeFixture(t *testing.T) *orgFixture {
	t.Helper()
	return newOrgFixtureWithIdentities(t, []identity.TenantID{"org-test-basic", "org-test-scope"}, []identity.UserID{"owner", "outsider"})
}

func slugNativeOperationService(t *testing.T, source *organizationpg.Service) *organizationpg.OperationService {
	t.Helper()
	query := kernel.CommandQueryPolicy{Authorization: fixturePolicy{}, Clock: clock.System{}, PolicyVersion: 1}
	keys, err := kernel.NewRequestKeyConfig("slug-native-read", [32]byte{0x51}, query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("slug-native-read", map[string][]byte{"slug-native-read": bytes.Repeat([]byte{0x52}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := organizationpg.NewOperationService(source, organizationpg.OperationServiceConfig{ConfigurationID: "slug-native-read", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x53}}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: keys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) {
		return "", errors.New("advisory read attempted organization allocation")
	}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestSlugAvailabilityUsesNativePrimaryWithoutMembership(t *testing.T) {
	f := slugNativeFixture(t)
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	core, err := organization.NewService(f.sessions, repository, fixturePolicy{}, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	result, err := core.SlugAvailable(f.ctx, organization.SlugAvailableRequest{Authentication: f.auth("org-test-basic", "outsider"), Slug: "candidate", CorrelationID: "slug-native"})
	if err != nil || !result.Available {
		t.Fatal("native authenticated nonmember cannot read a free candidate", err)
	}
	facade := slugNativeOperationService(t, f.service)
	request := organization.SlugAvailableRequest{Authentication: f.auth("org-test-basic", "outsider"), Slug: "candidate", CorrelationID: "slug-native"}
	if result, err = facade.SlugAvailable(f.ctx, request); err != nil || !result.Available {
		t.Fatal("operation facade did not delegate authenticated advisory read", err)
	}
	var effects int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("advisory read created a command effect", err)
	}
	createSlugOrganization(t, f, "org-test-basic", "taken", "candidate")
	if result, err = facade.SlugAvailable(f.ctx, request); err != nil || result.Available {
		t.Fatal("operation facade retained stale positive availability", err)
	}
	if result, err = f.service.SlugAvailable(f.ctx, request); err != nil || result.Available {
		t.Fatal("occupied native slug reported free", err)
	}
	request.Authentication = f.auth("org-test-scope", "outsider")
	if result, err = f.service.SlugAvailable(f.ctx, request); err != nil || !result.Available {
		t.Fatal("another tenant's slug blocked candidate", err)
	}
	// This fixture transition proves the installed retained-row occupancy rule,
	// not the separately covered archive lifecycle or its external effects.
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state='archived',version=version+1 WHERE tenant_id='org-test-basic' AND organization_id='taken'`); err != nil {
		t.Fatal(err)
	}
	request.Authentication = f.auth("org-test-basic", "outsider")
	if result, err = f.service.SlugAvailable(f.ctx, request); err != nil || result.Available {
		t.Fatal("archived retained slug reported free", err)
	}
	duplicate := prepareSlugOrganization(t, f, "org-test-basic", "duplicate", "candidate")
	if result, err := f.service.Execute(f.ctx, duplicate); !errors.Is(err, organization.ErrConflict) || result.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("advisory occupancy diverged from archived-row create uniqueness", err, result.Receipt.Outcome)
	}
}

func prepareSlugOrganization(t *testing.T, f *orgFixture, tenant, id, slug string) organizationpg.PreparedCommand {
	t.Helper()
	prepared, err := f.service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), ID: organization.ID(id), Name: "Slug candidate", Slug: slug, CorrelationID: "slug-create"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func createSlugOrganization(t *testing.T, f *orgFixture, tenant, id, slug string) {
	t.Helper()
	committedTeam(t, f, prepareSlugOrganization(t, f, tenant, id, slug))
}

func TestSlugAvailabilityNeverReservesAgainstCompetingCreates(t *testing.T) {
	f := slugNativeFixture(t)
	request := organization.SlugAvailableRequest{Authentication: f.auth("org-test-basic", "outsider"), Slug: "contended", CorrelationID: "slug-native"}
	if result, err := f.service.SlugAvailable(f.ctx, request); err != nil || !result.Available {
		t.Fatal("free candidate unavailable before competing creates", err)
	}
	prepared := []organizationpg.PreparedCommand{
		prepareSlugOrganization(t, f, "org-test-basic", "first", request.Slug),
		prepareSlugOrganization(t, f, "org-test-basic", "second", request.Slug),
	}
	type attempt struct {
		result organization.StoreResult
		err    error
	}
	results := make(chan attempt, 2)
	var workers sync.WaitGroup
	for _, command := range prepared {
		workers.Go(func() {
			result, err := f.service.Execute(f.ctx, command)
			results <- attempt{result: result, err: err}
		})
	}
	workers.Wait()
	close(results)
	committed, conflicted := 0, 0
	for result := range results {
		switch {
		case result.err == nil && result.result.Receipt.Outcome == identity.CommitOutcomeCommitted:
			committed++
		case errors.Is(result.err, organization.ErrConflict) && result.result.Receipt.Outcome == identity.CommitOutcomeNotCommitted:
			conflicted++
		default:
			t.Fatal("competing create returned neither commitment nor conflict", result.err, result.result.Receipt.Outcome)
		}
	}
	if committed != 1 || conflicted != 1 {
		t.Fatal("availability replaced authoritative uniqueness", committed, conflicted)
	}
	if result, err := f.service.SlugAvailable(f.ctx, request); err != nil || result.Available {
		t.Fatal("previous positive result survived actual competing create", err)
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.organizations WHERE tenant_id='org-test-basic' AND slug='contended'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("competing creates did not retain exactly one occupied slug", err)
	}
}

type slugNativePolicy struct {
	calls    int
	callback func(context.Context, authorization.DecisionContext) (authorization.Outcome, error)
}

func (p *slugNativePolicy) Decide(ctx context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
	if decision.Request.Action == authorization.Action(organization.SlugAvailable) {
		p.calls++
		outcome, err := p.callback(ctx, decision)
		return authorization.Decision{Outcome: outcome, Revision: 1}, err
	}
	return (fixturePolicy{}).Decide(ctx, decision)
}

func TestSlugAvailabilityNativeAuthorityWithdrawal(t *testing.T) {
	for _, variant := range []string{"denied", "policy-error", "late-policy", "session-revoked", "user-suspended", "credential-revoked", "occupancy-changed", "canceled"} {
		t.Run(variant, func(t *testing.T) {
			f := slugNativeFixture(t)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			policy := &slugNativePolicy{}
			policy.callback = func(ctx context.Context, decision authorization.DecisionContext) (authorization.Outcome, error) {
				if decision.Request.Subject.ID != "outsider" || decision.Request.Tenant != "org-test-basic" || decision.Request.Resource.Type != "organization.slug" || decision.Request.Resource.ID != "candidate" {
					t.Fatal("native policy substituted subject, tenant or candidate")
				}
				if variant == "denied" {
					return authorization.Deny, nil
				}
				if variant == "policy-error" {
					return 0, errors.New("private native policy diagnostic")
				}
				if policy.calls != 2 {
					return authorization.Allow, nil
				}
				var err error
				switch variant {
				case "late-policy":
					return authorization.Deny, nil
				case "session-revoked":
					_, err = f.pool.Raw().Exec(ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='outsider'`)
				case "user-suspended":
					_, err = f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id='org-test-basic' AND user_id='outsider'`)
				case "credential-revoked":
					_, err = f.pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false,version=version+1 WHERE tenant_id='org-test-basic' AND user_id='outsider'`)
				case "occupancy-changed":
					createSlugOrganization(t, f, "org-test-basic", "late", "candidate")
				case "canceled":
					cancel()
				}
				return authorization.Allow, err
			}
			service := listPolicyService(t, f, policy)
			request := organization.SlugAvailableRequest{Authentication: f.auth("org-test-basic", "outsider"), Slug: "candidate", CorrelationID: "slug-native"}
			result, err := service.SlugAvailable(ctx, request)
			want := organization.ErrForbidden
			if variant == "policy-error" {
				want = organization.ErrUnavailable
			}
			if variant == "canceled" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || result.Available {
				t.Fatal("native withdrawal disclosed availability", err)
			}
		})
	}
}

func TestSlugAvailabilityNativeInputAndSourceFailure(t *testing.T) {
	f := slugNativeFixture(t)
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{"", "Upper", "-start", "end-", "a/b", strings.Repeat("a", 64)} {
		query := organization.OrganizationSlugQuery{TenantID: "org-test-basic", Slug: slug}
		if result, err := repository.ReadOrganizationSlug(f.ctx, query); !errors.Is(err, organization.ErrInvalidInput) || result.Available {
			t.Fatal("native reader accepted invalid candidate", err)
		}
	}
	request := organization.SlugAvailableRequest{Authentication: f.auth("org-test-basic", "outsider"), Slug: "candidate", CorrelationID: "slug-native"}
	invalid := request
	invalid.CorrelationID = "bad correlation"
	if result, err := f.service.SlugAvailable(f.ctx, invalid); !errors.Is(err, organization.ErrInvalidInput) || result.Available {
		t.Fatal("native service accepted malformed correlation", err)
	}
	invalid = request
	invalid.Authentication.TenantID = "org-test-scope"
	if result, err := f.service.SlugAvailable(f.ctx, invalid); !errors.Is(err, organization.ErrForbidden) || result.Available {
		t.Fatal("native bearer crossed tenant boundary", err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if result, err := f.service.SlugAvailable(ctx, request); !errors.Is(err, context.Canceled) || result.Available {
		t.Fatal("canceled native read disclosed availability", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE organization.organizations RENAME TO unavailable_slug_organizations`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := f.pool.Raw().Exec(cleanup, `ALTER TABLE organization.unavailable_slug_organizations RENAME TO organizations`); err != nil {
			t.Error("owned slug source fault restoration failed", err)
		}
	}()
	if result, err := f.service.SlugAvailable(f.ctx, request); !errors.Is(err, organization.ErrUnavailable) || result.Available {
		t.Fatal("native source outage fabricated availability", err)
	}
}
