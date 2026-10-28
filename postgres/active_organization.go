package postgres

import (
	"context"
	"crypto/subtle"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

// PrepareActiveOrganization freezes an exact authenticated password/bearer
// session CAS and target membership. Empty OrganizationID explicitly clears.
// Execute enlists the session owner's effect in this participant's one Work.
// The opt-in contributor and selected native session reader are required.
func (s *Service) PrepareActiveOrganization(ctx context.Context, r organization.ActiveOrganizationRequest, network string) (PreparedCommand, error) {
	if s == nil || s.core == nil || s.participant == nil || ctx == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	if s.participant.selection == nil {
		return PreparedCommand{}, organization.ErrForbidden
	}
	command, err := s.core.PrepareActiveSet(ctx, r)
	if err != nil {
		return PreparedCommand{}, err
	}
	return s.prepare(ctx, command, network)
}

// GetActiveOrganization reads current session-owned selection with current
// membership, aggregate epoch and action policy. Denials return a zero view;
// neither reads nor selection change the original activity or bearer lifetime.
func (s *Service) GetActiveOrganization(ctx context.Context, r organization.ActiveOrganizationReadRequest) (organization.ActiveOrganizationView, error) {
	if s == nil || s.core == nil || s.participant == nil || ctx == nil {
		return organization.ActiveOrganizationView{}, organization.ErrInvalidInput
	}
	if s.participant.selection == nil {
		return organization.ActiveOrganizationView{}, organization.ErrForbidden
	}
	return s.core.GetActive(ctx, r)
}

func activeMemberFields(m organization.Member, c ContributorConfig) []identity.FeatureField {
	return []identity.FeatureField{
		text("active.member-role", string(m.Role)), number("active.member-version", m.Version), number("active.member-authorization", m.AuthorizationVersion),
		number("active.maximum-members", c.MaximumMembers), number("active.maximum-per-user", c.MaximumPerUser), number("active.maximum-per-tenant", c.MaximumPerTenant),
	}
}

func (p *Contributor) mapActiveOrganization(x organization.CommandInput) (identity.Command, error) {
	if p.selection == nil {
		return identity.Command{}, organization.ErrForbidden
	}
	f, err := sessionpg.OrganizationSelectionFields(x.ActiveOrganization, x.ActiveOrganizationValidUntil)
	if err != nil {
		return identity.Command{}, organization.ErrInvalidInput
	}
	f = append(f, activeMemberFields(x.Actor, p.config)...)
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: x.Binding, Operation: organization.ActiveSet.Descriptor(), Fields: f}, x.Bearer)
	if err == nil {
		_, err = p.decode(command)
	}
	if err != nil {
		return identity.Command{}, err
	}
	return command, err
}

func (p *Contributor) decodeActiveOrganization(spec identity.FeatureCommandSpec) (nativeCommand, error) {
	bad := func() (nativeCommand, error) { return nativeCommand{}, organization.ErrInvalidInput }
	if p.selection == nil || spec.Binding.UserID != identity.UserID(spec.Binding.ActorID) {
		return bad()
	}
	transition, until, err := sessionpg.OrganizationSelectionFromFields(spec.Binding, spec.Fields)
	if err != nil {
		return bad()
	}
	c, _ := transition.Bindings()
	values := map[string]identity.FeatureValue{}
	for _, field := range spec.Fields {
		switch {
		case strings.HasPrefix(field.Name, "organization.active."):
			values[strings.TrimPrefix(field.Name, "organization.")] = field.Value
		case strings.HasPrefix(field.Name, "source-session."), strings.HasPrefix(field.Name, "organization.selection."), strings.HasPrefix(field.Name, "counter."):
		default:
			return bad()
		}
	}
	for _, f := range activeMemberFields(organization.Member{}, p.config) {
		v, ok := values[strings.TrimPrefix(f.Name, "organization.")]
		if !ok || v.Kind != f.Value.Kind {
			return bad()
		}
	}
	if len(values) != 6 || values["active.maximum-members"].Uint64 != p.config.MaximumMembers || values["active.maximum-per-user"].Uint64 != p.config.MaximumPerUser || values["active.maximum-per-tenant"].Uint64 != p.config.MaximumPerTenant {
		return bad()
	}
	role := organization.Role(values["active.member-role"].Text)
	version, policy := values["active.member-version"].Uint64, values["active.member-authorization"].Uint64
	id := organization.ID(c.Selection.OrganizationID)
	if id == "" {
		if role != "" || version != 0 || policy != 0 {
			return bad()
		}
	} else {
		key, err := organization.OrganizationSessionScope(spec.Binding.TenantID, id)
		if err != nil || key != c.Selection.Authority.ScopeKey || c.Selection.Authority.Version == 0 || !role.Valid() || version == 0 || policy == 0 {
			return bad()
		}
	}
	if _, _, _, err := sessionpg.OriginalOrganizationPasswordSessionAdmission(p.config.Profile, c.Source, spec.Binding); err != nil {
		return bad()
	}
	if _, err := c.Source.CSRFState().Bindings(); err == nil {
		return bad()
	}
	return nativeCommand{spec: spec, operation: organization.ActiveSet, selection: transition, original: c.Source, until: until, org: organization.Organization{TenantID: spec.Binding.TenantID, ID: id, Version: c.Selection.Authority.Version, Active: id != ""}, actor: organization.Member{TenantID: spec.Binding.TenantID, OrganizationID: id, UserID: spec.Binding.UserID, Role: role, Version: version, AuthorizationVersion: policy, Active: id != ""}}, nil
}

func (p *Contributor) validateActiveOrganizationPlan(c nativeCommand, plan kernel.CommandPlan) error {
	original, _ := c.original.Bindings()
	if plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != organization.ActiveSet.Descriptor() || plan.SubjectType != "session" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "session.organization_changed.v1" || plan.Lifecycle.BeforeVersion != original.Version || plan.Lifecycle.AfterVersion != original.Version+1 || len(plan.Audits) != 1 || plan.Audits[0].EventType != string(organization.ActiveSet) || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.Delivery != nil || plan.CommandCounters == nil {
		return organization.ErrInvalidInput
	}
	return nil
}

func (s *Service) activeOrganizationPlan(command identity.Command, counters kernel.CommandCounterPlan, now time.Time, n nativeCommand) (kernel.CommandPlan, error) {
	original, _ := n.original.Bindings()
	b := n.spec.Binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, organization.ErrUnavailable
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: string(organization.ActiveSet), Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(original.Version, 10), "aggregate.after_version": strconv.FormatUint(original.Version+1, 10), "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, organization.ErrInvalidInput
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, n.spec.Operation, "session", seed)
	if err != nil {
		return kernel.CommandPlan{}, organization.ErrInvalidInput
	}
	return s.config.Coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: append([]kernel.ContributorDescriptor(nil), s.contributors...), Feature: &kernel.FeatureRegistration{Contributor: s.participant.Descriptor(), Operation: n.spec.Operation}, SubjectType: "session", Lifecycle: &kernel.LifecyclePlan{EventType: "session.organization_changed.v1", BeforeVersion: original.Version, AfterVersion: original.Version + 1}, CommandCounters: &counters, Audits: []kernel.AuditPlan{{EventType: string(organization.ActiveSet), SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
}

func (p *Contributor) requireActiveOrganizationTarget(ctx context.Context, w kernel.Work, c nativeCommand) error {
	if c.org.ID == "" {
		return nil
	}
	transition, _ := c.selection.Bindings()
	if err := p.repository.RequireOrganizationSession(ctx, w, p, transition.Successor); err != nil {
		return err
	}
	// The aggregate lock above protects the target's membership lifecycle.
	// Compare the exact originally admitted member, not merely its existence.
	var role string
	var version, policy string
	rows, err := w.Query(ctx, `SELECT role,version::text,authorization_version::text FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND state='active' FOR SHARE`, string(c.spec.Binding.TenantID), string(c.org.ID), string(c.spec.Binding.UserID))
	if err := one(rows, err, &role, &version, &policy); err != nil {
		return err
	}
	if organization.Role(role) != c.actor.Role || version != strconv.FormatUint(c.actor.Version, 10) || policy != strconv.FormatUint(c.actor.AuthorizationVersion, 10) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *Contributor) applyActiveOrganization(ctx context.Context, w kernel.Work, c nativeCommand, command identity.Command) (identity.FeatureReceipt, error) {
	original, _ := c.original.Bindings()
	bearer, ok := command.SessionToken()
	if !ok {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(bearer.Token())
	key, present := p.config.LookupKeys[original.Lookup.KeyVersion]
	if err != nil || !present {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	digest, err := token.Digest(key, string(original.TenantID))
	if err != nil || digest.KeyVersion != original.Lookup.KeyVersion || subtle.ConstantTimeCompare(digest.Sum[:], original.Lookup.Sum[:]) != 1 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	// Session->organization/member is the shared global lock order. The effect
	// must acquire family/session locks before any target organization admission.
	if err := p.selection.Lock(ctx, w, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.requireActiveOrganizationTarget(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return p.selection.Apply(ctx, w, p, command)
}
