//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"testing"
	"time"
)

func selectionOrganizationService(t *testing.T, pool *database.Pool, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, keys map[string][32]byte, material func(string) []byte, selectedPrimary ...*passwordpg.ActionPrimarySource) *organizationpg.Service {
	return selectionOrganizationServiceWithRoles(t, pool, sessions, profile, lookup, keys, material, organization.DynamicRoleConfig{}, selectedPrimary...)
}

func selectionOrganizationServiceWithRoles(t *testing.T, pool *database.Pool, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, keys map[string][32]byte, material func(string) []byte, roles organization.DynamicRoleConfig, selectedPrimary ...*passwordpg.ActionPrimarySource) *organizationpg.Service {
	return selectionOrganizationServiceProfile(t, pool, sessions, profile, lookup, keys, material, roles, nil, selectedPrimary...)
}

func selectionOrganizationServiceProfile(t *testing.T, pool *database.Pool, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, keys map[string][32]byte, material func(string) []byte, roles organization.DynamicRoleConfig, domainSource *organizationpg.DomainEvidenceSource, selectedPrimary ...*passwordpg.ActionPrimarySource) *organizationpg.Service {
	t.Helper()
	participant, configuration := selectionOrganizationComposition(t, pool, sessions, profile, lookup, keys, material, roles, domainSource, nil, true, selectedPrimary...)
	service, err := organizationpg.NewService(participant, configuration)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func selectionOrganizationComposition(t *testing.T, pool *database.Pool, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, keys map[string][32]byte, material func(string) []byte, roles organization.DynamicRoleConfig, domainSource *organizationpg.DomainEvidenceSource, requiredSignals []string, active bool, selectedPrimary ...*passwordpg.ActionPrimarySource) (*organizationpg.Contributor, organizationpg.ServiceConfig) {
	t.Helper()
	repository, e := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	teams := organization.TeamConfig{}
	domains := organization.DomainConfig{}
	if domainSource != nil {
		domains.EvidenceMaximumAge = time.Hour
	}
	var primary *passwordpg.ActionPrimarySource
	var proofAudience string
	var lifecycle organization.LifecycleConfig
	var archive, restore *passwordpg.ActionPrimarySource
	if len(selectedPrimary) > 0 {
		primary = selectedPrimary[0]
		proofAudience = transferAudience
	}
	if len(selectedPrimary) == 3 {
		archive, restore = selectedPrimary[1], selectedPrimary[2]
		lifecycle = organization.LifecycleConfig{Version: 1, ProofAudience: transferAudience}
	}
	participant, e := organizationpg.NewContributor(repository, organizationpg.ContributorConfig{Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, LookupKeys: map[uint32]session.DigestKey{11: lookup}, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams, Domains: domains, DomainEvidence: domainSource, DynamicRoles: roles, ActiveOrganization: active, OwnerTransferPrimary: primary, Lifecycle: lifecycle, ArchivePrimary: archive, RestorePrimary: restore})
	if e != nil {
		t.Fatal(e)
	}
	policyConfig := baselineRiskPolicyConfig(9, false, false)
	if requiredSignals != nil {
		for i := range policyConfig.Profiles {
			if policyConfig.Profiles[i].Class == risk.Privileged {
				policyConfig.Profiles[i].RequiredSignals = requiredSignals
			}
		}
	}
	policy, e := risk.NewPolicy(policyConfig)
	if e != nil {
		t.Fatal(e)
	}
	digest, e := risk.NewCounterDigestKey(1, material("counter"))
	if e != nil {
		t.Fatal(e)
	}
	evidence, e := risk.NewEvidenceKey(1, material("risk-evidence"), material("risk-seal"))
	if e != nil {
		t.Fatal(e)
	}
	counters, e := riskpg.NewRepository(riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{digest}}, EnforceLockouts: true})
	if e != nil {
		t.Fatal(e)
	}
	domain, e := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	audits, e := postgres.NewIdentityContributor(postgres.Config{})
	if e != nil {
		t.Fatal(e)
	}
	outbox, e := lifecyclepg.NewContributor()
	if e != nil {
		t.Fatal(e)
	}
	registry, e := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, counters, participant})
	if e != nil {
		t.Fatal(e)
	}
	authorize, e := fixtureAuthorization()
	if e != nil {
		t.Fatal(e)
	}
	coordinator, e := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}})
	if e != nil {
		t.Fatal(e)
	}
	configuration := organizationpg.ServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams, Domains: domains, DynamicRoles: roles, OwnerTransferAudience: proofAudience, Lifecycle: lifecycle, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		_, e := identity.ParseSubjectID(string(id))
		return errors.Join(ctx.Err(), e)
	}}, Sessions: sessions, Authorization: authorize, Risk: counters, Coordinator: coordinator, Registry: registry}
	return participant, configuration
}

func (f *activeOrganizationFixture) requireSupportedSelectionCounterProfile(t *testing.T) {
	t.Helper()
	for _, signals := range [][]string{{"velocity"}, {"velocity", "status"}, {"velocity", "captcha"}} {
		for _, active := range []bool{false, true} {
			participant, configuration := selectionOrganizationComposition(t, f.pool, f.sessions, f.profile, f.lookup, f.keys, f.material, organization.DynamicRoleConfig{}, nil, signals, active)
			service, err := organizationpg.NewService(participant, configuration)
			if active && len(signals) != 1 {
				if service != nil || !errors.Is(err, organization.ErrInvalidInput) {
					t.Fatal("selected facade silently ignored configured non-counter signal", signals, err)
				}
			} else if err != nil || service == nil {
				t.Fatal("selected velocity or unchanged unselected composition denied", active, signals, err)
			}
		}
	}
}
