package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

// ServiceConfig supplies actual native owners from the composition's immutable
// registry. Risk must select native protected counters and current lockouts;
// migrations are applied before use. The supplied coordinator is the sole
// transaction/result owner and must register Contributor, Risk, kernel, audit
// and lifecycle outbox. Core and contributor limits/policy must agree exactly.
// These borrowed owners must outlive calls. No background resources are owned.
type ServiceConfig struct {
	Core          organization.Config
	Sessions      *session.SessionService
	Authorization authorization.Service
	Risk          *riskpg.Repository
	Coordinator   *kernel.Coordinator
	Registry      *kernel.ContributorRegistry
}

// Service provides native public organization operations without application-
// written domain stores, transaction glue, private authority or retry journals.
// Explicit bearer transport and uncached organization selection are supported;
// HTTP/browser transport, active selections and other session profiles are not.
type Service struct {
	core         *organization.Service
	participant  *Contributor
	config       ServiceConfig
	contributors []kernel.ContributorDescriptor
}

func NewService(p *Contributor, c ServiceConfig) (*Service, error) {
	if p == nil || p.repository == nil || c.Sessions == nil || c.Authorization == nil || c.Risk == nil || c.Coordinator == nil || c.Registry == nil || c.Core.PolicyID != p.config.PolicyID || c.Core.PolicyVersion != p.config.PolicyVersion || c.Core.MaximumMembers != p.config.MaximumMembers || c.Core.MaximumPerUser != p.config.MaximumPerUser || c.Core.MaximumPerTenant != p.config.MaximumPerTenant || c.Core.Teams != p.config.Teams {
		return nil, organization.ErrInvalidInput
	}
	core, e := organization.NewService(c.Sessions, p.repository, c.Authorization, c.Core)
	if e != nil {
		return nil, e
	}
	selected := []kernel.ContributorDescriptor{}
	counts := map[string]int{}
	for _, d := range c.Registry.Descriptors() {
		switch {
		case d == p.repository.directory.Descriptor(), d == p.Descriptor(), d == c.Risk.Descriptor(), d.Owner == "audit/postgres", d == (kernel.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}):
			selected = append(selected, d)
			counts[d.Owner]++
		}
	}
	if len(selected) != 5 || counts["identity/postgres"] != 1 || counts["organization/postgres"] != 1 || counts["identity/risk/postgres"] != 1 || counts["audit/postgres"] != 1 || counts["outbox/postgres"] != 1 {
		return nil, organization.ErrInvalidInput
	}
	return &Service{core: core, participant: p, config: c, contributors: selected}, nil
}

// PreparedCommand retains one exact original keyed command and native plan.
// Zero is invalid; copies share immutable bearer custody, not another attempt.
// Preserve this value across bounded Execute retries; preparing again would
// create a different observation and is not an idempotent retry. After expiry
// or an unknown outcome, use Recovery with current authentication instead.
type PreparedCommand struct{ state *preparedState }
type preparedState struct {
	owner   *Service
	core    organization.Command
	native  identity.Command
	plan    kernel.CommandPlan
	binding identity.CommandBinding
}

// Recovery contains only the original exact safe scope, never a bearer/proof.
// Persist it when an operation may outlive the process. It confers no access:
// Recover authenticates the current caller and applies current policy again.
type Recovery struct{ Binding identity.CommandBinding }

func (p PreparedCommand) Recovery() (Recovery, error) {
	if p.state == nil {
		return Recovery{}, organization.ErrInvalidInput
	}
	return Recovery{Binding: p.state.binding}, nil
}
func (PreparedCommand) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.PreparedCommand(redacted)"))
}
func (PreparedCommand) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (PreparedCommand) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (ServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.ServiceConfig(redacted)"))
}
func (ServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (ServiceConfig) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// PrepareCreate authenticates/authorizes, then freezes native privileged counter
// admission and the plan using primary time. Network is a trusted canonical
// full client IP resolved by the embedding transport, not an arbitrary header.
// No organization mutation/reservation occurs until Execute.
func (s *Service) PrepareCreate(ctx context.Context, r organization.CreateRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareCreate(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) PrepareAddMember(ctx context.Context, r organization.MemberRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareAddMember(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}

// PrepareUpdate freezes a bounded Name/Slug replacement with current owner or
// administrator admission, the expected organization version and native
// privileged counters. Execute performs the sole durable attempt; Recover
// reconciles its exact command without replaying a lost commit response.
func (s *Service) PrepareUpdate(ctx context.Context, r organization.UpdateRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareUpdate(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) PrepareRemoveMember(ctx context.Context, r organization.MemberRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareRemoveMember(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}

func (s *Service) prepare(ctx context.Context, c organization.Command, network string) (PreparedCommand, error) {
	if ctx == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	x, e := c.Input()
	if e != nil {
		return PreparedCommand{}, e
	}
	if x.Session.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return PreparedCommand{}, organization.ErrForbidden
	}
	native, e := s.participant.MapCommand(c)
	if e != nil {
		return PreparedCommand{}, e
	}
	var at time.Time
	if e = s.participant.repository.pool.Raw().QueryRow(bounded, `SELECT clock_timestamp()`).Scan(&at); e != nil {
		return PreparedCommand{}, storageError(bounded, e)
	}
	native, counters, e := s.config.Risk.PrepareCommandCounters(native, risk.Subject{Actor: string(x.Binding.ActorID), Resource: x.Binding.RecordID, Network: network}, at.UTC())
	if e != nil {
		return PreparedCommand{}, organization.ErrForbidden
	}
	plan, e := s.plan(native, counters, at.UTC())
	if e != nil {
		return PreparedCommand{}, e
	}
	return PreparedCommand{state: &preparedState{owner: s, core: c, native: native, plan: plan, binding: x.Binding}}, nil
}

func (s *Service) plan(c identity.Command, counters kernel.CommandCounterPlan, now time.Time) (kernel.CommandPlan, error) {
	spec, ok := c.Feature()
	if !ok {
		return kernel.CommandPlan{}, organization.ErrInvalidInput
	}
	n, e := s.participant.decode(c)
	if e != nil {
		return kernel.CommandPlan{}, e
	}
	event, action := events(n.operation)
	builder, e := audit.NewBuilder(audit.BuilderConfig{})
	if e != nil {
		return kernel.CommandPlan{}, organization.ErrUnavailable
	}
	b := spec.Binding
	seed, e := builder.Build(audit.RecordInput{OccurredAt: now, Action: action, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "organization", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "organization", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(n.org.Version, 10), "aggregate.after_version": strconv.FormatUint(n.org.Version+1, 10), "retention.class": "protected"}})
	if e != nil {
		return kernel.CommandPlan{}, organization.ErrInvalidInput
	}
	digest, e := kernel.FeatureAuditBindingDigest(b, spec.Operation, "organization", seed)
	if e != nil {
		return kernel.CommandPlan{}, organization.ErrInvalidInput
	}
	return s.config.Coordinator.PrepareCommandPlan(b, c, kernel.CommandPlan{Contributors: append([]kernel.ContributorDescriptor(nil), s.contributors...), Feature: &kernel.FeatureRegistration{Contributor: s.participant.Descriptor(), Operation: spec.Operation}, SubjectType: "organization", Lifecycle: &kernel.LifecyclePlan{EventType: event, BeforeVersion: n.org.Version, AfterVersion: n.org.Version + 1}, CommandCounters: &counters, Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
}

// Execute attempts the exact prepared mutation once through the native scoped
// UnitOfWork. A repeated identical command reuses the coordinator's receipt;
// it never regenerates IDs, authority, counters, effects or credentials.
func (s *Service) Execute(ctx context.Context, p PreparedCommand) (organization.StoreResult, error) {
	if s == nil || ctx == nil || p.state == nil || p.state.owner != s {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	u := &unitOfWork{service: s, prepared: p.state}
	return s.core.Execute(ctx, p.state.core, u)
}

func (s *Service) Get(ctx context.Context, r organization.ReadRequest) (organization.View, error) {
	if s == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.core.Get(ctx, r)
}
func (s *Service) ListMembers(ctx context.Context, r organization.ReadRequest) (organization.View, error) {
	if s == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.core.ListMembers(ctx, r)
}

// Recover discloses only the exact original scoped historical outcome after
// native current-session authentication and current recovery authorization.
// Membership operations additionally require the original actor's current
// durable membership; removal cannot become authority via a retained receipt.
// It never rebuilds or executes the original command, renews its expiry or
// reveals bearer material. Unknown remains unknown until primary reconciliation.
func (s *Service) Recover(ctx context.Context, a organization.Authentication, r Recovery) (organization.StoreResult, error) {
	if ctx == nil || s == nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	b := r.Binding
	op := organization.Operation(b.OperationID)
	if isTeamMutation(op) && s.config.Core.Teams.MaximumTeams == 0 {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	if isTeamLifecycle(op) && s.config.Core.Teams.LifecycleVersion != 1 {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	if b.ValidateFor(op.Descriptor()) != nil || b.ActorKind != authorization.SubjectUser || b.PolicyID != s.config.Core.PolicyID || b.PolicyVersion != s.config.Core.PolicyVersion || b.TenantID != a.TenantID {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	token, e := session.ParseToken(a.Bearer.Token())
	if e != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	credential, e := session.NewCredential(session.CredentialBearer, token)
	if e != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	observed, e := s.config.Sessions.Get(bounded, session.GetRequest{TenantID: a.TenantID, Credential: credential})
	if e != nil {
		return organization.StoreResult{}, storageError(bounded, e)
	}
	if observed.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	original, e := observed.Session.Bindings()
	if e != nil || string(original.UserID) != string(b.ActorID) || original.TenantID != b.TenantID {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	actorBinding := b
	actorBinding.UserID = original.UserID
	if _, _, _, e = sessionpg.OriginalSessionAdmission(s.participant.config.Profile, observed.Session, actorBinding); e != nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	var admission organization.View
	if op != organization.Create {
		view, readErr := s.core.Get(bounded, organization.ReadRequest{Authentication: a, OrganizationID: organization.ID(b.RecordID), CorrelationID: b.CorrelationID})
		if readErr != nil {
			return organization.StoreResult{}, readErr
		}
		admission = view
		if op == organization.Update || isTeamMutation(op) {
			if e = s.authorizeUpdateRecovery(bounded, b, view); e != nil {
				return organization.StoreResult{}, e
			}
		}
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Core.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}, Tenant: authorization.TenantID(b.TenantID), Environment: authorization.Environment{Time: s.config.Core.Clock.Now()}}}
	u := &unitOfWork{service: s, recovery: &recoveryInput{binding: b, caller: caller, observed: observed, credential: credential, organization: admission.Organization, member: admission.Actor}}
	return u.Recover(bounded, b.CommandID)
}

// Historical command disclosure is not an org:update grant. Recheck the same
// current management role and organization policy used by preparation, before
// the kernel separately enforces its exact identity.user disclosure policy.
func (s *Service) authorizeUpdateRecovery(ctx context.Context, b identity.CommandBinding, view organization.View) (err error) {
	defer func() {
		if recover() != nil {
			err = organization.ErrUnavailable
		}
	}()
	if view.Actor.Role != organization.RoleOwner && view.Actor.Role != organization.RoleAdministrator {
		return organization.ErrForbidden
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Core.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(b.RecordID), Attributes: authorization.Attributes{"organization.policy-version": authorization.StringValue(strconv.FormatUint(view.Organization.Version, 10))}}, Tenant: authorization.TenantID(b.TenantID), Environment: authorization.Environment{Time: s.config.Core.Clock.Now()}}}
	decision, err := s.config.Authorization.Decide(ctx, caller)
	if err != nil {
		return storageError(ctx, err)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return organization.ErrForbidden
	}
	return nil
}

type recoveryInput struct {
	binding      identity.CommandBinding
	caller       authorization.DecisionContext
	observed     session.GetResult
	credential   session.Credential
	organization organization.Organization
	member       organization.Member
}

// Recovery policy callbacks are not authority leases. Re-read the submitted
// credential through the native session owner and compare the exact primary
// organization/member admission after callbacks, without recursively invoking
// policy or renewing the original recovery observation's validity interval.
func (s *Service) revalidateRecovery(ctx context.Context, r *recoveryInput) error {
	if r.observed.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.ErrForbidden
	}
	b := r.binding
	current, err := s.config.Sessions.Get(ctx, session.GetRequest{TenantID: b.TenantID, Credential: r.credential})
	if err != nil {
		return storageError(ctx, err)
	}
	if current.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return organization.ErrForbidden
	}
	bound, err := current.Session.Bindings()
	if err != nil || bound.TenantID != b.TenantID || string(bound.UserID) != string(b.ActorID) {
		return organization.ErrForbidden
	}
	actorBinding := b
	actorBinding.UserID = bound.UserID
	if _, _, _, err = sessionpg.OriginalSessionAdmission(s.participant.config.Profile, current.Session, actorBinding); err != nil {
		return organization.ErrForbidden
	}
	if r.organization.Version != 0 {
		view, err := s.participant.repository.Read(ctx, organization.Query{Operation: organization.Get, TenantID: b.TenantID, ActorID: identity.UserID(b.ActorID), OrganizationID: organization.ID(b.RecordID)})
		if err != nil {
			return err
		}
		if view.Organization != r.organization || view.Actor != r.member {
			return organization.ErrForbidden
		}
		scope, err := OrganizationAuthorityScope(b.TenantID, view.Organization.ID, view.Actor.UserID)
		if err != nil {
			return err
		}
		store, err := authority.NewAuthorityStore(s.participant.repository.pool.Raw(), s.participant.repository.maximum)
		if err != nil {
			return organization.ErrUnavailable
		}
		live, err := store.Get(ctx, scope)
		if err != nil {
			return publicTeamAuthorityError(err)
		}
		if live.Version != view.Actor.AuthorizationVersion {
			return organization.ErrForbidden
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	now := s.config.Core.Clock.Now()
	if current.ValidateAt(now) != nil || r.observed.ValidateAt(now) != nil {
		return organization.ErrForbidden
	}
	return nil
}

type unitOfWork struct {
	service  *Service
	prepared *preparedState
	recovery *recoveryInput
}

var _ organization.UnitOfWork = (*unitOfWork)(nil)

func (u *unitOfWork) Execute(ctx context.Context, c organization.Command) (organization.StoreResult, error) {
	if u == nil || u.service == nil || u.prepared == nil || c != u.prepared.core || ctx == nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	s, p := u.service, u.prepared
	reservation, receipt, e := s.config.Coordinator.ReserveCommand(ctx, p.binding, p.native, p.plan)
	if e != nil || reservation == (kernel.Reservation{}) {
		return mutationResult(p.binding, receipt), e
	}
	w, e := s.config.Coordinator.Begin(ctx, reservation)
	if e != nil {
		return mutationResult(p.binding, unknown(p.binding)), e
	}
	defer s.config.Coordinator.Abort(w, identity.UnavailableError{})
	receipt, e = s.config.Coordinator.ApplyFeature(ctx, w, p.native)
	if e != nil {
		receipt, e = s.config.Coordinator.Abort(w, e)
		return mutationResult(p.binding, receipt), e
	}
	receipt, e = s.config.Coordinator.Commit(w, receipt)
	return mutationResult(p.binding, receipt), e
}

func (u *unitOfWork) Recover(ctx context.Context, id identity.CommandID) (organization.StoreResult, error) {
	if u == nil || u.service == nil || u.recovery == nil || ctx == nil || u.recovery.binding.CommandID != id {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	r := u.recovery
	s := u.service
	if err := s.revalidateRecovery(ctx, r); err != nil {
		return organization.StoreResult{}, err
	}
	b := r.binding
	q := identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	receipt, e := s.config.Coordinator.RecoverFeatureCommand(ctx, q, r.caller)
	if err := s.revalidateRecovery(ctx, r); err != nil {
		return organization.StoreResult{}, err
	}
	if receipt.Outcome != identity.CommitOutcomeInvalid && receipt.Binding != b {
		return organization.StoreResult{}, organization.ErrUnavailable
	}
	return mutationResult(b, receipt), e
}

func mutationResult(b identity.CommandBinding, r identity.CommandResult) organization.StoreResult {
	return organization.StoreResult{Receipt: r, OrganizationID: organization.ID(b.RecordID), MemberID: b.UserID}
}
func unknown(b identity.CommandBinding) identity.CommandResult {
	return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: organization.Operation(b.OperationID).Descriptor()}}
}
