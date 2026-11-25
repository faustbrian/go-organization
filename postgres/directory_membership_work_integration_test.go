//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
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

type directoryMembershipWorkOwner struct {
	repository      *organizationpg.Repository
	update          organizationpg.DirectoryMembershipUpdate
	effect          organizationpg.DirectoryMembershipEffect
	command         identity.Command
	input           organizationpg.DirectoryMembershipInput
	withdraw        bool
	denyFinal       bool
	foreignOrg      organization.ID
	applyCalls      int
	recordSuccessor bool
}

func (p *directoryMembershipWorkOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: p.FeatureOperations()[0].SchemaID, Version: 1}
}

func (p *directoryMembershipWorkOwner) FeatureOperations() []identity.FeatureOperation {
	operation := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-user-admission", SchemaID: "sso.directory-user-admission", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if p.withdraw {
		operation.OperationID = "identity.sso.directory-sync.apply-user-deprovision"
		operation.SchemaID = "sso.directory-user-deprovision"
	}
	return []identity.FeatureOperation{operation}
}

func (p *directoryMembershipWorkOwner) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || plan.Lifecycle == nil || plan.Lifecycle.BeforeVersion != p.update.BeforeVersion() || plan.Lifecycle.AfterVersion != p.update.AfterVersion() {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directoryMembershipWorkOwner) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.applyCalls++
	locked, err := p.repository.LockDirectoryMembershipUpdate(ctx, w, p, c, p.update)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	effect, err := p.repository.ApplyDirectoryMembershipUpdate(ctx, w, p, c, p.update, locked)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.effect = effect
	if p.recordSuccessor {
		if err := p.repository.RecordDirectoryMembershipSuccessor(ctx, w, p, c, p.effect); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: p.update.BeforeVersion(), AfterVersion: p.update.AfterVersion()}, nil
}

func (p *directoryMembershipWorkOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.repository.RequireDirectoryMembershipEffect(ctx, w, p, c, p.update, p.effect); err != nil {
		return err
	}
	sourceOwner := p.input.Organization
	if p.foreignOrg != "" {
		sourceOwner.OrganizationID = p.foreignOrg
	} else if p.denyFinal {
		sourceOwner.Version++
	}
	return p.repository.RequireDirectoryMembershipSourceOwner(ctx, w, p, c, p.input.Source, sourceOwner, p.effect)
}

func (*directoryMembershipWorkOwner) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func directoryMembershipNativeWork(t *testing.T, f *orgFixture, p *directoryMembershipWorkOwner, input organizationpg.DirectoryMembershipInput) (*kernel.Coordinator, identity.Command, kernel.CommandPlan) {
	t.Helper()
	var err error
	p.input = input
	p.update, err = organizationpg.NewDirectoryMembershipUpdate(input)
	if err != nil {
		t.Fatal("prepare directory membership effect", err)
	}
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
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, p})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(f.pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x55}}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: fixturePolicy{}, Clock: clock.System{}, PolicyVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	op := p.FeatureOperations()[0]
	binding := identity.CommandBinding{CommandID: commandID(t), TenantID: input.Source.TenantID, UserID: input.Source.UserID, ActorID: input.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "directory", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "directory-member-child", RecordID: p.update.RecordID()}
	field, err := p.update.Field()
	if err != nil {
		t.Fatal(err)
	}
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: []identity.FeatureField{field}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	const subject = "directory_membership"
	record, err := b.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": subject, "aggregate.id": binding.RecordID, "aggregate.before_version": strconv.FormatUint(p.update.BeforeVersion(), 10), "aggregate.after_version": strconv.FormatUint(p.update.AfterVersion(), 10), "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(binding, op, subject, record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PrepareCommandPlan(binding, p.command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, SubjectType: subject, Lifecycle: &kernel.LifecyclePlan{EventType: "sso.directory_sync.membership_changed.v1", BeforeVersion: p.update.BeforeVersion(), AfterVersion: p.update.AfterVersion()}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "protected", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, p.command, plan
}

func TestDirectoryMembershipNativeWorkWithdrawsOnlyEffectiveSource(t *testing.T) {
	const tenant = "org-test-basic"
	f := newOrgFixture(t, organizationpg.CredentialAuthorityMigrationSource{Version: 305}, organizationpg.DirectoryMembershipMigrationSource{Version: 306})
	f.create(t, tenant)
	f.add(t, tenant, "second", organization.RoleAdministrator, 1)
	f.add(t, tenant, "outsider", organization.RoleMember, 2)
	f.create(t, "org-test-scope")
	f.add(t, "org-test-scope", "member", organization.RoleMember, 1)
	store, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	scope := organizationpg.DirectoryMembershipSource{TenantID: tenant, OrganizationID: metadataOrganization, UserID: "member", ProviderID: "provider-one", ConnectionID: "connection-one", ResourceID: "resource-one"}
	other := scope
	other.ProviderID, other.ConnectionID, other.ResourceID = "provider-two", "connection-two", "resource-two"
	var foreignFinalOrg organization.ID
	currentAuthority := func(t testing.TB, tenant identity.TenantID, target identity.UserID) (organization.CredentialAuthorityObservation, error) {
		t.Helper()
		return store.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: tenant, OrganizationID: metadataOrganization, ActorID: target})
	}
	apply := func(t *testing.T, source organizationpg.DirectoryMembershipSource, withdraw, denyFinal, wantCommit bool) {
		t.Helper()
		observed, err := store.ObserveDirectoryMembership(f.ctx, source)
		if err != nil {
			t.Fatal("observe exact source and canonical member", err)
		}
		org, err := currentAuthority(t, source.TenantID, "")
		if err != nil {
			t.Fatal(err)
		}
		action := organizationpg.DirectoryMembershipGrant
		if withdraw {
			action = organizationpg.DirectoryMembershipWithdraw
		}
		input := organizationpg.DirectoryMembershipInput{Source: source, ActorID: "directory-service", User: identity.User{TenantID: source.TenantID, ID: source.UserID, Status: identity.StatusActive, Version: 1}, Organization: org, MemberVersion: observed.Member.Version, MemberAuthorizationVersion: observed.Member.AuthorizationVersion, ExpectedVersion: observed.ContributionVersion, Action: action, MaximumMembers: 20, MaximumPerUser: 10}
		if withdraw {
			input.User = identity.User{}
		}
		p := &directoryMembershipWorkOwner{repository: store, withdraw: withdraw, denyFinal: denyFinal, foreignOrg: foreignFinalOrg}
		c, command, plan := directoryMembershipNativeWork(t, f, p, input)
		got, err := executeDirectoryTeamNative(f.ctx, c, command, plan)
		if wantCommit {
			if err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.Feature == nil || got.Feature.BeforeVersion != observed.ContributionVersion || got.Feature.AfterVersion != observed.ContributionVersion+1 {
				t.Fatal("exact directory grant or withdrawal did not commit", got.Outcome, err)
			}
			replay, err := executeDirectoryTeamNative(f.ctx, c, command, plan)
			if err != nil || !reflect.DeepEqual(got, replay) || p.applyCalls != 1 {
				t.Fatal("original directory receipt did not replay unchanged", err)
			}
		} else if err == nil || got.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("unproven or late-denied source changed authority", got.Outcome, err)
		}
	}

	apply(t, scope, false, false, true)
	granted, err := currentAuthority(t, tenant, "member")
	if err != nil || granted.Actor.Role != organization.RoleMember || granted.Actor.Version != 1 || granted.Version != 4 {
		t.Fatal("genuine source did not create canonical, scoped membership", err)
	}
	foreignResource := scope
	foreignResource.ResourceID = "different-resource"
	if observed, err := store.ObserveDirectoryMembership(f.ctx, foreignResource); !errors.Is(err, organization.ErrConflict) || observed != (organizationpg.DirectoryMembershipObservation{}) {
		t.Fatal("same connection rebound an existing resource's contribution", err)
	}
	read := organization.ReadRequest{Authentication: f.auth(tenant, "member"), OrganizationID: metadataOrganization, CorrelationID: "directory-member-current-access"}
	if _, err := f.service.Get(f.ctx, read); err != nil {
		t.Fatal("effective directory member cannot use an authenticated organization reader", err)
	}
	apply(t, other, false, false, true)
	apply(t, scope, true, false, true)
	retained, err := currentAuthority(t, tenant, "member")
	if err != nil || retained.Actor != granted.Actor || retained.Version != granted.Version {
		t.Fatal("first source withdrawal revoked unrelated effective access or changed its epoch", err)
	}
	apply(t, other, true, true, false)
	retained, err = currentAuthority(t, tenant, "member")
	if err != nil || retained.Actor != granted.Actor || retained.Version != granted.Version {
		t.Fatal("late denial did not restore the effective member and authority", err)
	}
	const unrelatedOrg = "directory-unrelated"
	// Give an unrelated organization the candidate successor version so version
	// equality cannot accidentally make it the original source owner.
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count) VALUES($1,$2,$3,'Unrelated owner fixture','active',$4::numeric,1,1)`, tenant, unrelatedOrg, unrelatedOrg, strconv.FormatUint(granted.Version+1, 10)); err != nil {
		t.Fatal("install a distinct live owner with the same successor version", err)
	}
	foreignFinalOrg = unrelatedOrg
	apply(t, other, true, true, false)
	foreignFinalOrg = ""
	apply(t, other, true, false, true)
	if _, err := currentAuthority(t, tenant, "member"); err == nil {
		t.Fatal("last directory source left the effective membership usable")
	}
	if _, err := f.service.Get(f.ctx, read); err == nil {
		t.Fatal("same authenticated session retained access after effective withdrawal")
	}
	removed, err := store.ObserveDirectoryMembership(f.ctx, other)
	if err != nil || removed.Member.Active || removed.Member.Version != granted.Actor.Version+1 || removed.Member.AuthorizationVersion != granted.Actor.AuthorizationVersion+1 {
		t.Fatal("withdrawal did not advance both canonical member and scoped authority", err)
	}
	for _, target := range []struct {
		tenant identity.TenantID
		user   identity.UserID
	}{{tenant, "owner"}, {tenant, "second"}, {tenant, "outsider"}, {"org-test-scope", "member"}} {
		if _, err := currentAuthority(t, target.tenant, target.user); err != nil {
			t.Fatalf("unrelated effective access was lost: %s/%s: %v", target.tenant, target.user, err)
		}
	}
	for _, local := range []identity.UserID{"owner", "second", "outsider"} {
		foreign := scope
		foreign.UserID = local
		apply(t, foreign, false, false, false)
	}
	var status string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT status FROM identity.users WHERE tenant_id=$1 AND user_id='member'`, tenant).Scan(&status); err != nil || status != "active" {
		t.Fatal("directory withdrawal modified global identity", err)
	}

	// A blocked global account still needs its independent directory grant
	// removed; a later unblock must not restore previously granted access.
	target := scope
	target.TenantID = "org-test-target"
	f.create(t, string(target.TenantID))
	apply(t, target, false, false, true)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='suspended',version=2 WHERE tenant_id=$1 AND user_id='member'`, string(target.TenantID)); err != nil {
		t.Fatal("set separate identity lifecycle fixture", err)
	}
	apply(t, target, true, false, true)
	if observed, err := store.ObserveDirectoryMembership(f.ctx, target); err != nil || observed.Member.Active || observed.Member.Version != 2 {
		t.Fatal("account block prevented durable removal of organization grant", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT status FROM identity.users WHERE tenant_id=$1 AND user_id='member'`, string(target.TenantID)).Scan(&status); err != nil || status != "suspended" {
		t.Fatal("directory withdrawal changed independent identity block", err)
	}
}
