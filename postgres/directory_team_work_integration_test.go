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
	if err := p.repository.ApplyDirectoryTeamGrantUpdate(ctx, w, p, c, p.update); err != nil {
		return identity.FeatureReceipt{}, err
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
	i := directoryTeamInput()
	i.Scope = organizationpg.DirectoryTeamGrantScope{TenantID: "org-test-basic", OrganizationID: metadataOrganization, ProviderID: "provider", ConnectionID: "connection", GroupID: "group-a", TeamID: "engineering", UserID: "member"}
	i.User.TenantID = "org-test-basic"
	return f, owner, coordinator, registry, i
}

func directoryTeamNativeCommand(t *testing.T, c *kernel.Coordinator, registry *kernel.ContributorRegistry, owner *directoryTeamWorkOwner, i organizationpg.DirectoryTeamGrantInput) (identity.Command, kernel.CommandPlan) {
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
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: owner.FeatureOperations()[0], Fields: []identity.FeatureField{field}})
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
