//go:build integration

package consumer_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

func TestOrganizationGenuineCreateTeamOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "team-create-operation")
}

type teamCreateAdmissionEvaluator struct{}

func (*teamCreateAdmissionEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && r.Action == authorization.Action(organization.CreateTeam) && r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(organization.CreateTeam) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}

type genuineTeamCreator interface {
	CreateTeam(context.Context, organization.CreateTeamOperationRequest, string) (organization.StoreResult, error)
}

func exerciseGenuineCreateTeams(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, owner, member organization.Authentication, ownerID, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, signinOwner func() organization.Authentication, logout reference.SessionService) {
	t.Helper()
	var history migrationList
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.TeamMigrationSource{Version: 7001}} {
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, steps...)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("actual team profile migrations", err)
	}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "team-create-consumer", Revision: 9, Evaluator: new(teamCreateAdmissionEvaluator)})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	authorize, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	source := func(primary *database.Pool, policy authorization.Service) *organizationpg.Service {
		return teamCreateConsumerSource(t, primary, sessions, profile, lookup, keys, material, policy)
	}
	build := func(primary *database.Pool, policy authorization.Service) *organizationpg.OperationService {
		query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
		requestKeys, err := kernel.NewRequestKeyConfig("team-create-consumer", keys["request"], query)
		if err != nil {
			t.Fatal(err)
		}
		custody, err := organizationpg.NewOperationCustodyConfig("team-create-consumer", map[string][]byte{"team-create-consumer": material("delivery-envelope")})
		if err != nil {
			t.Fatal(err)
		}
		s, err := organizationpg.NewOperationService(source(primary, policy), organizationpg.OperationServiceConfig{ConfigurationID: "team-create-consumer-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) { return "", organization.ErrUnavailable }})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	invoke := func(primary *database.Pool, r organization.CreateTeamOperationRequest) (organization.StoreResult, error) {
		s := build(primary, authorize)
		p, ok := any(s).(genuineTeamCreator)
		if !ok {
			t.Fatal("public original-key team creation missing")
		}
		return p.CreateTeam(ctx, r, "127.0.0.1")
	}
	newID := func() organization.ID {
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		return organization.ID(id)
	}
	createOrg := func(label string) organization.ID {
		id := newID()
		s := source(pool, authorize)
		p, err := s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: id, Name: "Team creation consumer", Slug: "team-create-" + label, CorrelationID: "team-create-setup"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if out, err := s.Execute(ctx, p); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual organization setup", err)
		}
		return id
	}
	request := func(org organization.ID, epoch uint64, label string) organization.CreateTeamOperationRequest {
		key, err := identity.NewIdempotencyKey([]byte("original-team-" + label))
		if err != nil {
			t.Fatal(err)
		}
		return organization.CreateTeamOperationRequest{Authentication: owner, IdempotencyKey: key, OrganizationID: org, TeamID: newID(), OrganizationVersion: epoch, Name: "Engineering", CorrelationID: "original-team-create"}
	}
	assertState := func(r organization.CreateTeamOperationRequest, teams, epoch, effects int) {
		t.Helper()
		var actualTeams, actualEpoch, actualEffects, memberships int
		err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.teams WHERE tenant_id=$1 AND organization_id=$2),(SELECT version FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2),(SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND operation='identity.organization.team.create'),(SELECT count(*) FROM organization.team_memberships WHERE tenant_id=$1 AND organization_id=$2)`, string(owner.TenantID), string(r.OrganizationID)).Scan(&actualTeams, &actualEpoch, &actualEffects, &memberships)
		if err != nil || actualTeams != teams || actualEpoch != epoch || actualEffects != effects || memberships != 0 {
			t.Fatal("team creation state/effects diverged", actualTeams, actualEpoch, actualEffects, memberships, err)
		}
	}
	assertEffects := func(original organization.StoreResult) {
		t.Helper()
		id, err := base64.RawURLEncoding.DecodeString(string(original.Receipt.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		var effects, events, audits int
		err = db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE command_id=$1 AND operation='identity.organization.team.create'),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$2 AND m.topic='team.created.v1'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$2 AND r.action='identity.organization.create_team' AND r.outcome=1)`, string(original.Receipt.Binding.CommandID), id).Scan(&effects, &events, &audits)
		if err != nil || effects != 1 || events != 1 || audits != 1 {
			t.Fatal("original team lost singleton protected history", effects, events, audits, err)
		}
	}
	r := request(createOrg("original"), 1, "original")
	original, err := invoke(pool, r)
	if err != nil || original.Receipt.Validate() != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted || original.OrganizationID != r.OrganizationID || original.Receipt.Feature == nil || original.Receipt.Feature.Operation != organization.CreateTeam.Descriptor() || original.Receipt.Feature.BeforeVersion != 1 || original.Receipt.Feature.AfterVersion != 2 {
		t.Fatal("actual original-key team creation", err)
	}
	view, err := source(pool, authorize).ListTeams(ctx, organization.TeamReadRequest{Authentication: owner, OrganizationID: r.OrganizationID, Limit: 10, CorrelationID: "original-team-primary"})
	if err != nil || len(view.Teams) != 1 || view.Teams[0].ID != r.TeamID || view.Teams[0].Name != r.Name || view.Teams[0].Version != 1 {
		t.Fatal("chosen empty team missing from actual primary", err)
	}
	assertState(r, 1, 2, 1)
	assertEffects(original)
	r.Authentication = signinOwner()
	r.CorrelationID = "reconstructed-fresh-session"
	if got, err := invoke(pool, r); err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal("fresh reconstructed team retry changed original", err)
	}
	if got, err := build(pool, authorize).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal("explicit original team history", err)
	}
	for _, variant := range []string{"team", "name", "epoch", "organization"} {
		changed := r
		switch variant {
		case "team":
			changed.TeamID = newID()
		case "name":
			changed.Name = "Other team"
		case "epoch":
			changed.OrganizationVersion++
		case "organization":
			changed.OrganizationID = newID()
		}
		if _, err := invoke(pool, changed); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("changed original team intent did not conflict", variant, err)
		}
	}
	denied := r
	denied.Authentication = member
	if got, err := invoke(pool, denied); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("nonmanager adopted original team", err)
	}
	denied = r
	denied.Authentication.TenantID = "foreign"
	if got, err := invoke(pool, denied); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign tenant adopted original team", err)
	}
	stale := request(r.OrganizationID, 1, "stale")
	if _, err := invoke(pool, stale); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("stale team epoch admitted", err)
	}
	second := request(r.OrganizationID, 2, "second")
	if got, err := invoke(pool, second); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("second permitted team denied", err)
	}
	over := request(r.OrganizationID, 3, "over-limit")
	if got, err := invoke(pool, over); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("real two-team quota bypassed", err)
	}
	assertState(r, 2, 3, 2)
	if got, err := invoke(pool, r); err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal("later organization epoch lost original team", err)
	}
	for _, boundary := range []string{"audit", "outbox"} {
		t.Run("atomic rollback "+boundary, func(t *testing.T) {
			bad := request(createOrg("rollback-"+boundary), 1, "rollback-"+boundary)
			table, condition := "audit.records", "NEW.action='identity.organization.create_team' AND NEW.outcome=1"
			if boundary == "outbox" {
				table, condition = "public.outbox_messages", "NEW.topic='team.created.v1'"
			}
			if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.fail_team_operation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION 'controlled team effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_team_operation BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.fail_team_operation()`); err != nil {
				t.Fatal(err)
			}
			out, failure := invoke(pool, bad)
			if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER fail_team_operation ON `+table+`; DROP FUNCTION organization.fail_team_operation()`); err != nil {
				t.Fatal(err)
			}
			if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("required team effect failure committed", failure)
			}
			if got, err := invoke(pool, bad); !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(got, out) {
				t.Fatal("aborted original team was executed again", err)
			}
			assertState(bad, 0, 1, 0)
		})
	}
	for _, mappingOnly := range []bool{true, false} {
		label := "domain-commit-loss"
		if mappingOnly {
			label = "mapping-commit-loss"
		}
		t.Run(label, func(t *testing.T) {
			bad := request(createOrg(label), 1, label)
			fault := new(commitResponseLoss)
			primary, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
					if err != nil {
						return nil, err
					}
					return &lossyCommitConn{Conn: conn, fault: fault}, nil
				}
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := primary.Close(cleanup); err != nil {
					t.Error(err)
				}
			}()
			fault.count.Store(-1)
			if mappingOnly {
				fault.count.Store(1)
			}
			fault.armed.Store(true)
			unknown, err := invoke(primary, bad)
			var ambiguity identity.UnknownCommitError
			if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" || errors.As(err, &ambiguity) && ambiguity.CommandID != unknown.Receipt.Binding.CommandID {
				t.Fatal("actual lost COMMIT lost original team scope", err)
			}
			for range 2 {
				got, err := invoke(pool, bad)
				if got.Receipt.Binding != unknown.Receipt.Binding {
					t.Fatal("ambiguous team retry allocated another command")
				}
				if mappingOnly {
					if !errors.As(err, &ambiguity) || got.Receipt.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("mapping-only team granted execution or invented outcome", err)
					}
				} else {
					if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("lost committed team did not recover", err)
					}
					assertEffects(got)
				}
			}
			got, err := build(pool, authorize).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: unknown.Receipt.Binding})
			if got.Receipt.Binding != unknown.Receipt.Binding || mappingOnly && (!errors.As(err, &ambiguity) || got.Receipt.Outcome != identity.CommitOutcomeUnknown) || !mappingOnly && (err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("explicit team recovery changed original classification", err)
			}
			if mappingOnly {
				assertState(bad, 0, 1, 0)
				raw, err := base64.RawURLEncoding.DecodeString(string(unknown.Receipt.Binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				var journals, claims int
				if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1)`, raw).Scan(&journals, &claims); err != nil || journals != 0 || claims != 0 {
					t.Fatal("mapping-only team created execution custody", err)
				}
			} else {
				assertState(bad, 1, 2, 1)
			}
		})
	}
	t.Run("same key contention has one original before recovery", func(t *testing.T) {
		contended := request(createOrg("contention"), 1, "contention")
		start := make(chan struct{})
		results := make(chan organization.StoreResult, 2)
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() { <-start; out, _ := invoke(pool, contended); results <- out })
		}
		close(start)
		wg.Wait()
		close(results)
		var winner organization.StoreResult
		for out := range results {
			if out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				if winner.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(out, winner) {
					t.Fatal("contenders committed different originals")
				}
				winner = out
			}
		}
		if winner.Receipt.Binding.CommandID == "" {
			t.Fatal("neither initial team contender committed")
		}
		assertState(contended, 1, 2, 1)
		assertEffects(winner)
		if got, err := invoke(pool, contended); err != nil || !reflect.DeepEqual(got, winner) {
			t.Fatal("contended team original was not recoverable", err)
		}
	})
	var independentOrg organization.ID
	for _, stage := range []string{"management", "query"} {
		t.Run("late manager withdrawal "+stage, func(t *testing.T) {
			org := createOrg("late-" + stage)
			plain := source(pool, authorize)
			p, err := plain.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: organization.RoleOwner, CorrelationID: "team-replacement-owner"}, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			if out, err := plain.Execute(ctx, p); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal(err)
			}
			selected := request(org, 2, "late-"+stage)
			out, err := invoke(pool, selected)
			if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal(err)
			}
			hook := &invitationCancellationPolicy{base: authorize}
			managementSeen, querySeen, withdrawn := false, false, false
			hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
				if withdrawn || d.Request.Action != authorization.Action(organization.CreateTeam) {
					return nil
				}
				switch string(d.Request.Resource.Type) {
				case "organization":
					managementSeen = true
					if stage != "management" {
						return nil
					}
				case "identity.user":
					if stage != "query" || !managementSeen {
						return nil
					}
					querySeen = true
				default:
					return nil
				}
				p, err := plain.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: member, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 3, UserID: ownerID, MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "team-withdraw-original-manager"}, "127.0.0.1")
				if err != nil {
					return err
				}
				out, err := plain.Execute(ctx, p)
				withdrawn = err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted
				if !withdrawn {
					return organization.ErrUnavailable
				}
				return nil
			}
			service := build(pool, hook)
			port, ok := any(service).(genuineTeamCreator)
			if !ok {
				t.Fatal("team operation missing")
			}
			denied, err := port.CreateTeam(ctx, selected, "127.0.0.1")
			if !errors.Is(err, organization.ErrForbidden) || !withdrawn || !managementSeen || stage == "query" && !querySeen || denied.Receipt.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("late withdrawn manager obtained original team", err)
			}
			assertState(selected, 1, 4, 1)
			assertEffects(out)
			independentOrg = org
		})
	}
	t.Run("actual logout denies saved original", func(t *testing.T) {
		r.Authentication = signinOwner()
		if got, err := invoke(pool, r); err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("fresh session lost original team before logout", err)
		}
		token, err := session.ParseToken(r.Authentication.Bearer.Token())
		if err != nil {
			t.Fatal(err)
		}
		credential, err := session.NewCredential(session.CredentialBearer, token)
		if err != nil {
			t.Fatal(err)
		}
		out, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: r.Authentication.TenantID, CommandID: commandID(t), CorrelationID: "team-create-signout", Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{})
		if err != nil || !out.SignedOut || out.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual team source logout", err)
		}
		if got, err := invoke(pool, r); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("logged-out actor recovered team", err)
		}
		if _, err := source(pool, authorize).ListTeams(ctx, organization.TeamReadRequest{Authentication: member, OrganizationID: independentOrg, Limit: 10, CorrelationID: "independent-team-owner"}); err != nil {
			t.Fatal("logout revoked independent owner", err)
		}
		assertState(r, 2, 3, 2)
		assertEffects(original)
	})
}

// This selected consumer composes actual native owners with a two-team quota;
// signup, verification, password credentials and sessions remain the public graph.
func teamCreateConsumerSource(t *testing.T, pool *database.Pool, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, keys map[string][32]byte, material func(string) []byte, authorize authorization.Service) *organizationpg.Service {
	t.Helper()
	repository, e := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	teams := organization.TeamConfig{Version: 1, MaximumTeams: 2, MaximumMembers: 100}
	participant, e := organizationpg.NewContributor(repository, organizationpg.ContributorConfig{Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, LookupKeys: map[uint32]session.DigestKey{11: lookup}, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams})
	if e != nil {
		t.Fatal(e)
	}
	policy, e := baselineRiskPolicy(9, false, false)
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
	audits, e := auditpg.NewIdentityContributor(auditpg.Config{})
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
	coordinator, e := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}})
	if e != nil {
		t.Fatal(e)
	}
	service, e := organizationpg.NewService(participant, organizationpg.ServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		_, e := identity.ParseSubjectID(string(id))
		return errors.Join(ctx.Err(), e)
	}}, Sessions: sessions, Authorization: authorize, Risk: counters, Coordinator: coordinator, Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	return service
}
