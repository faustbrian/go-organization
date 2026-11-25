//go:build integration

package postgres_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This trusted test participant proves the organization seam with real Work;
// it is not production service-account authentication or SSO source admission.
type directoryTeamWorkOwner struct {
	repository                                *organizationpg.Repository
	update                                    organizationpg.DirectoryTeamGrantUpdate
	role                                      *organizationpg.DirectoryTeamRoleUpdate
	roleLock                                  organizationpg.DirectoryTeamRoleLock
	roleSource                                organizationpg.DirectoryTeamRoleSource
	roleOrganization                          organization.CredentialAuthorityObservation
	reconstruct, corruptAfterApply, denyFinal bool
	applyCalls, finalCalls                    int
}

func (*directoryTeamWorkOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.directory-team-membership", Version: 1}
}
func (*directoryTeamWorkOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-child", SchemaID: "sso.directory-team-membership", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (p *directoryTeamWorkOwner) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	s, ok := c.Feature()
	if !ok || s.Operation != p.FeatureOperations()[0] || plan.Lifecycle == nil || plan.Lifecycle.BeforeVersion != p.update.BeforeVersion() || plan.Lifecycle.AfterVersion != p.update.AfterVersion() {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *directoryTeamWorkOwner) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.applyCalls++
	if p.reconstruct {
		s, _ := c.Feature()
		var err error
		c, err = identity.NewFeatureCommand(s)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.role == nil {
		if err := p.repository.ApplyDirectoryTeamGrantUpdate(ctx, w, p, c, p.update); err != nil {
			return identity.FeatureReceipt{}, err
		}
	} else {
		var err error
		p.roleLock, err = p.repository.LockDirectoryTeamRoleUpdate(ctx, w, p, c, *p.role)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.repository.ApplyDirectoryTeamRoleUpdate(ctx, w, p, c, *p.role, p.roleLock); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.corruptAfterApply {
		if _, err := w.Exec(ctx, `UPDATE organization.directory_team_grants SET active=false WHERE tenant_id='org-test-basic' AND group_id='group-a'`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: p.update.BeforeVersion(), AfterVersion: p.update.AfterVersion()}, nil
}
func (p *directoryTeamWorkOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	p.finalCalls++
	if p.denyFinal {
		return identity.ForbiddenError{}
	}
	if p.role != nil {
		if err := p.repository.RequireDirectoryTeamRoleUpdate(ctx, w, p, c, *p.role, p.roleLock); err != nil {
			return err
		}
		return p.repository.RequireDirectoryTeamRoleSourceOwner(ctx, w, p, c, p.roleSource, p.roleOrganization, p.roleLock)
	}
	return p.repository.RequireDirectoryTeamGrantUpdate(ctx, w, p, c, p.update)
}
func (*directoryTeamWorkOwner) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func directoryTeamNativeFixture(t *testing.T) (*orgFixture, *directoryTeamWorkOwner, *kernel.Coordinator, *kernel.ContributorRegistry, organizationpg.DirectoryTeamGrantInput) {
	t.Helper()
	f := newOrgFixture(t, organizationpg.TeamMigrationSource{Version: 303}, organizationpg.TeamLifecycleMigrationSource{Version: 304}, organizationpg.CredentialAuthorityMigrationSource{Version: 305}, organizationpg.DirectoryTeamGrantMigrationSource{Version: 306})
	f.teams = organization.TeamConfig{Version: 1, MaximumTeams: 2, MaximumMembers: 10, LifecycleVersion: 1}
	f.compose(t)
	f.create(t, "org-test-basic")
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, "org-test-basic", "engineering", 2))
	owner, coordinator, registry := directoryTeamWorkCoordinator(t, f)
	i := directoryTeamInput()
	i.Scope = organizationpg.DirectoryTeamGrantScope{TenantID: "org-test-basic", OrganizationID: metadataOrganization, ProviderID: "provider", ConnectionID: "connection", GroupID: "group-a", TeamID: "engineering", UserID: "member"}
	i.User.TenantID = "org-test-basic"
	return f, owner, coordinator, registry, i
}

func directoryTeamWorkCoordinator(t *testing.T, f *orgFixture) (*directoryTeamWorkOwner, *kernel.Coordinator, *kernel.ContributorRegistry) {
	t.Helper()
	r, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	owner := &directoryTeamWorkOwner{repository: r}
	domain, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, owner})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(f.pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x55}}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: fixturePolicy{}, Clock: clock.System{}, PolicyVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return owner, coordinator, registry
}

type directoryTeamRoleTarget struct {
	source         organizationpg.DirectoryTeamRoleSource
	bindingVersion uint64
}

func directoryTeamNativeCommand(t *testing.T, c *kernel.Coordinator, registry *kernel.ContributorRegistry, owner *directoryTeamWorkOwner, i organizationpg.DirectoryTeamGrantInput, roles ...directoryTeamRoleTarget) (identity.Command, kernel.CommandPlan) {
	t.Helper()
	var err error
	owner.update, err = organizationpg.NewDirectoryTeamGrantUpdate(i)
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: commandID(t), TenantID: i.Scope.TenantID, UserID: i.Scope.UserID, ActorID: i.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: owner.FeatureOperations()[0].OperationID, PolicyID: "directory", PolicyVersion: 1, SchemaID: "sso.directory-team-membership", SchemaVersion: 1, CorrelationID: "directory-child", RecordID: owner.update.RecordID()}
	field, err := owner.update.Field()
	if err != nil {
		t.Fatal(err)
	}
	fields := []identity.FeatureField{field}
	owner.role = nil
	if len(roles) == 1 {
		update, err := organizationpg.NewDirectoryTeamRoleUpdate(owner.update, roles[0].source, roles[0].bindingVersion)
		if err != nil {
			t.Fatal(err)
		}
		owner.role = &update
		owner.roleSource = roles[0].source
		owner.roleOrganization, err = owner.repository.ObserveCredentialAuthority(t.Context(), organization.CredentialAuthorityQuery{TenantID: i.Scope.TenantID, OrganizationID: i.Scope.OrganizationID})
		if err != nil {
			t.Fatal(err)
		}
		role, err := update.Field()
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, role)
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: owner.FeatureOperations()[0], Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "directory.team-membership", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "team_membership", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "team_membership", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(owner.update.BeforeVersion(), 10), "aggregate.after_version": strconv.FormatUint(owner.update.AfterVersion(), 10), "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, owner.FeatureOperations()[0], "team_membership", record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: owner.FeatureOperations()[0]}, SubjectType: "team_membership", Lifecycle: &kernel.LifecyclePlan{EventType: "directory.team-membership.changed.v1", BeforeVersion: owner.update.BeforeVersion(), AfterVersion: owner.update.AfterVersion()}, Audits: []kernel.AuditPlan{{EventType: "directory.team-membership", SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "protected", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return command, plan
}

func executeDirectoryTeamNative(ctx context.Context, c *kernel.Coordinator, command identity.Command, plan kernel.CommandPlan) (identity.CommandResult, error) {
	s, _ := command.Feature()
	reservation, result, err := c.ReserveCommand(ctx, s.Binding, command, plan)
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		return result, err
	}
	w, err := c.Begin(ctx, reservation)
	if err != nil {
		return result, err
	}
	defer c.Abort(w, identity.UnavailableError{})
	result, err = c.ApplyFeature(ctx, w, command)
	if err != nil {
		return c.Abort(w, err)
	}
	return c.Commit(w, result)
}

func TestDirectoryTeamGrantNativeWorkCommitReplayWithdrawalAndRollback(t *testing.T) {
	f, owner, coordinator, registry, input := directoryTeamNativeFixture(t)
	command, plan := directoryTeamNativeCommand(t, coordinator, registry, owner, input)
	for range 2 {
		got, err := executeDirectoryTeamNative(f.ctx, coordinator, command, plan)
		if err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.Feature == nil || got.Feature.BeforeVersion != 0 || got.Feature.AfterVersion != 1 {
			t.Fatal("native source apply or replay", err, got.Outcome)
		}
	}
	if owner.applyCalls != 1 || owner.finalCalls != 1 {
		t.Fatal("replay repeated source writes or final custody was absent")
	}
	observation, err := owner.repository.ObserveDirectoryTeamMembership(f.ctx, input.Scope)
	if err != nil || !observation.Source || observation.Local || observation.Version != 1 {
		t.Fatal("committed exact source", err)
	}
	input.Active, input.ExpectedVersion = false, 1
	command, plan = directoryTeamNativeCommand(t, coordinator, registry, owner, input)
	got, err := executeDirectoryTeamNative(f.ctx, coordinator, command, plan)
	if err != nil || got.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native source withdrawal", err)
	}
	observation, err = owner.repository.ObserveDirectoryTeamMembership(f.ctx, input.Scope)
	if err != nil || observation.Source || observation.Local || observation.Version != 2 {
		t.Fatal("withdrawal did not retain source tombstone", err)
	}
	input.Active, input.ExpectedVersion = true, 2
	for _, mode := range []string{"late source change", "final admission withdrawn", "reconstructed command", "stale team"} {
		t.Run(mode, func(t *testing.T) {
			owner.corruptAfterApply, owner.denyFinal, owner.reconstruct = mode == "late source change", mode == "final admission withdrawn", mode == "reconstructed command"
			candidate := input
			if mode == "stale team" {
				candidate.TeamVersion++
			}
			command, plan := directoryTeamNativeCommand(t, coordinator, registry, owner, candidate)
			got, err := executeDirectoryTeamNative(f.ctx, coordinator, command, plan)
			if err == nil || got.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("denied source operation committed", mode)
			}
			observation, err := owner.repository.ObserveDirectoryTeamMembership(f.ctx, input.Scope)
			if err != nil || observation.Source || observation.Version != 2 {
				t.Fatal("denied operation escaped rollback", mode, err)
			}
		})
	}
}

func TestDirectoryTeamRoleWorkAdvancesAuthorityAndPreservesIndependentContributions(t *testing.T) {
	f, view := directoryTeamRolePermissionFixture(t)
	owner, coordinator, registry := directoryTeamWorkCoordinator(t, f)
	source := organizationpg.DirectoryTeamRoleSource{
		Scope:            organizationpg.DirectoryTeamGrantScope{TenantID: "org-test-basic", OrganizationID: metadataOrganization, UserID: "member", TeamID: "engineering", ProviderID: "provider", ConnectionID: "connection", GroupID: "group-a"},
		MemberResourceID: "source-member", RoleID: "reader", ProviderVersion: 2, MappingVersion: 3, ConnectionVersion: 4,
	}
	another := source
	another.Scope.GroupID = "group-b"
	reader, err := owner.repository.WithDirectoryTeamRoles(func(_ context.Context, claims []organizationpg.DirectoryTeamRoleSource) ([]bool, error) {
		current := make([]bool, len(claims))
		for i, claim := range claims {
			current[i] = claim == source || claim == another
		}
		return current, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := organization.NewService(f.configuration.Sessions, reader, f.configuration.Authorization, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	query := organization.Query{Operation: organization.CheckPermission, TenantID: source.Scope.TenantID, ActorID: source.Scope.UserID,
		OrganizationID: source.Scope.OrganizationID, Limit: 10, IncludeTeamRoles: true}
	read := func(allow bool) organization.View {
		t.Helper()
		out, err := reader.Read(f.ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		if allow {
			count = 1
		}
		if len(out.DynamicRoles) != count || allow && out.DynamicRoles[0].ID != "reader" {
			t.Fatal("unexpected effective roles after protected directory write")
		}
		decision, err := service.CheckPermission(f.ctx, organization.PermissionCheckRequest{
			Authentication: f.auth(string(query.TenantID), string(query.ActorID)), OrganizationID: query.OrganizationID,
			OrganizationVersion: out.Organization.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "directory-role",
		})
		if err != nil || (decision.Outcome == authorization.Allow) != allow {
			t.Fatal("native CheckPermission disagrees with exact owned roles", err)
		}
		return out
	}
	prepare := func(s organizationpg.DirectoryTeamRoleSource, active bool) (identity.Command, kernel.CommandPlan) {
		t.Helper()
		obs, err := owner.repository.ObserveDirectoryTeamMembership(f.ctx, s.Scope)
		if err != nil {
			t.Fatal(err)
		}
		i := directoryTeamInput()
		i.Scope, i.User.TenantID, i.Active = s.Scope, s.Scope.TenantID, active
		i.OrganizationVersion, i.CredentialVersion = obs.OrganizationVersion, obs.CredentialVersion
		i.MemberVersion, i.MemberAuthorizationVersion, i.TeamVersion = obs.MemberVersion, obs.MemberAuthorizationVersion, obs.TeamVersion
		i.User.Version, i.ExpectedVersion = obs.UserVersion, obs.Version
		binding := uint64(0)
		if active {
			binding = view.TeamRoleBinding.Version
		}
		return directoryTeamNativeCommand(t, coordinator, registry, owner, i, directoryTeamRoleTarget{source: s, bindingVersion: binding})
	}
	run := func(command identity.Command, plan kernel.CommandPlan) identity.CommandResult {
		t.Helper()
		got, err := executeDirectoryTeamNative(f.ctx, coordinator, command, plan)
		if err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.Feature == nil {
			t.Fatal("original directory role command did not commit", err, got.Outcome)
		}
		return got
	}
	before := read(false)
	first, firstPlan := prepare(source, true)
	grant := run(first, firstPlan)
	after := read(true)
	if replay := run(first, firstPlan); replay.Binding != grant.Binding || replay.AuditEventID != grant.AuditEventID || owner.applyCalls != 1 {
		t.Fatal("exact replay wrote again or lost the original receipt")
	}
	if after.Organization.Version != before.Organization.Version+1 || after.Actor.Version != before.Actor.Version ||
		after.Actor.AuthorizationVersion != before.Actor.AuthorizationVersion+1 || after.Actor.Role != organization.RoleMember {
		t.Fatal("directory role did not advance only its organization and scoped authority")
	}
	second, secondPlan := prepare(another, true)
	run(second, secondPlan)
	one, onePlan := prepare(source, false)
	run(one, onePlan)
	surviving := read(true)
	rejected, rejectedPlan := prepare(another, false)
	owner.denyFinal = true
	if got, err := executeDirectoryTeamNative(f.ctx, coordinator, rejected, rejectedPlan); err == nil || got.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("late denial left a committed withdrawal", err)
	}
	if afterRollback := read(true); afterRollback.Organization.Version != surviving.Organization.Version || afterRollback.Actor != surviving.Actor {
		t.Fatal("late denial changed persisted authorization")
	}
	owner.denyFinal = false
	foreign, foreignPlan := prepare(another, false)
	owner.roleSource.ConnectionVersion++
	if got, err := executeDirectoryTeamNative(f.ctx, coordinator, foreign, foreignPlan); err == nil || got.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("wrong source accepted the organization successor", err)
	}
	if afterMismatch := read(true); afterMismatch.Organization.Version != surviving.Organization.Version || afterMismatch.Actor != surviving.Actor {
		t.Fatal("source mismatch escaped rollback")
	}
	last, lastPlan := prepare(another, false)
	withdrawal := run(last, lastPlan)
	current := read(false)
	if replay := run(last, lastPlan); replay.Binding != withdrawal.Binding || replay.AuditEventID != withdrawal.AuditEventID {
		t.Fatal("withdrawal replay lost the original receipt")
	}
	if current.Organization.Version != surviving.Organization.Version+1 || current.Actor.AuthorizationVersion != surviving.Actor.AuthorizationVersion+1 {
		t.Fatal("last withdrawal did not invalidate the exact authority once")
	}
	legacy, err := owner.repository.ObserveDirectoryTeamMembership(f.ctx, another.Scope)
	if err != nil || legacy.Local || legacy.Source || legacy.Version != 2 {
		t.Fatal("source withdrawal lost the base tombstone or touched local grants", err)
	}
}
