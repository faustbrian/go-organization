//go:build integration

package postgres_test

import (
	"context"
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

type managedSCIMMembershipOwner struct {
	repository        *organizationpg.Repository
	input             organizationpg.DirectoryMembershipInput
	update            organizationpg.DirectoryMembershipUpdate
	boundUpdate       *organizationpg.DirectoryMembershipUpdate
	effect            organizationpg.DirectoryMembershipEffect
	command           identity.Command
	projectionVersion uint64
	denyFinal         bool
	grantBeforeFinal  bool
	applyCalls        int
}

func (*managedSCIMMembershipOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "scim/postgres", ContractID: "identity.scim.managed", Version: 1}
}

func (*managedSCIMMembershipOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "scim", OperationID: "identity.scim.user-delete", SchemaID: "identity.scim.user-delete.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential}}
}

func (p *managedSCIMMembershipOwner) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || plan.Lifecycle == nil || plan.Lifecycle.BeforeVersion != p.projectionVersion || plan.Lifecycle.AfterVersion != p.projectionVersion+1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *managedSCIMMembershipOwner) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.applyCalls++
	locked, err := p.repository.LockDirectoryMembershipUpdate(ctx, w, p, c, p.update)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.effect, err = p.repository.ApplyDirectoryMembershipUpdate(ctx, w, p, c, p.update, locked)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.grantBeforeFinal {
		s := p.input.Source
		_, err := w.Exec(ctx, `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active) VALUES($1,$2,$3,$4::numeric,$5,$6,$7,1,true)`, string(s.TenantID), string(s.OrganizationID), string(s.UserID), strconv.FormatUint(p.input.MemberVersion, 10), string(s.ProviderID), string(s.ConnectionID), string(s.ResourceID))
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: p.projectionVersion, AfterVersion: p.projectionVersion + 1}, nil
}

func (p *managedSCIMMembershipOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.denyFinal {
		return identity.ForbiddenError{}
	}
	if err := p.repository.RequireDirectoryMembershipEffect(ctx, w, p, c, p.update, p.effect); err != nil {
		return err
	}
	return p.repository.RequireDirectoryMembershipSourceOwner(ctx, w, p, c, p.input.Source, p.input.Organization, p.effect)
}

func (*managedSCIMMembershipOwner) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func managedSCIMMembershipWork(t *testing.T, f *orgFixture, p *managedSCIMMembershipOwner) (*kernel.Coordinator, identity.Command, kernel.CommandPlan) {
	t.Helper()
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
	binding := identity.CommandBinding{CommandID: commandID(t), TenantID: p.input.Source.TenantID, UserID: p.input.Source.UserID, ActorID: p.input.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "directory", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "managed-scim-delete", RecordID: string(p.input.Source.ResourceID)}
	field, err := p.update.Field()
	if p.boundUpdate != nil {
		field, err = p.boundUpdate.Field()
	}
	if err != nil {
		t.Fatal(err)
	}
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: []identity.FeatureField{field}})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	const subject = "scim_user"
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": subject, "aggregate.id": binding.RecordID, "aggregate.before_version": strconv.FormatUint(p.projectionVersion, 10), "aggregate.after_version": strconv.FormatUint(p.projectionVersion+1, 10), "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(binding, op, subject, record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PrepareCommandPlan(binding, p.command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, SubjectType: subject, Lifecycle: &kernel.LifecyclePlan{EventType: "scim.user_deleted.v1", BeforeVersion: p.projectionVersion, AfterVersion: p.projectionVersion + 1}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "protected", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, p.command, plan
}

func TestManagedSCIMMembershipWithdrawalOriginalWork(t *testing.T) {
	for _, scenario := range []string{"absent", "local", "last-source", "other-source", "retired", "replaced", "other-resource", "late-grant", "grant-before-final", "late-denial", "wrong-projection", "wrong-source-state"} {
		t.Run(scenario, func(t *testing.T) {
			const tenant = "org-test-basic"
			f := newOrgFixture(t, organizationpg.CredentialAuthorityMigrationSource{Version: 305}, organizationpg.DirectoryMembershipMigrationSource{Version: 306})
			f.create(t, tenant)
			store, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			source := organizationpg.DirectoryMembershipSource{TenantID: tenant, OrganizationID: metadataOrganization, UserID: "member", ProviderID: "provider-one", ConnectionID: "connection-one", ResourceID: "resource-one"}
			if scenario != "absent" {
				f.add(t, tenant, "member", organization.RoleMember, 1)
			}
			seedGrant := func(resource string, active bool) {
				t.Helper()
				if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active) VALUES($1,$2,$3,1,$4,$5,$6,7,$7)`, tenant, metadataOrganization, "member", "provider-one", "connection-one", resource, active); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "last-source", "other-source", "replaced", "late-denial", "wrong-projection", "wrong-source-state":
				seedGrant("resource-one", true)
			case "retired":
				seedGrant("resource-one", false)
			case "other-resource":
				seedGrant("another-resource", true)
			}
			if scenario == "replaced" {
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET version=2,role='administrator' WHERE tenant_id=$1 AND organization_id=$2 AND user_id='member'`, tenant, metadataOrganization); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "other-source" {
				if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active) VALUES($1,$2,'member',1,'other-provider','other-connection','other-resource',1,true)`, tenant, metadataOrganization); err != nil {
					t.Fatal(err)
				}
			}
			observed, err := store.ObserveManagedSCIMDirectoryMembership(f.ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			org, err := store.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: tenant, OrganizationID: metadataOrganization})
			if err != nil {
				t.Fatal(err)
			}
			input := organizationpg.DirectoryMembershipInput{Source: source, ActorID: "directory-service", Organization: org, MemberVersion: observed.Member.Version, MemberAuthorizationVersion: observed.Member.AuthorizationVersion, ExpectedVersion: observed.ContributionVersion, Action: organizationpg.DirectoryMembershipWithdraw}
			update, err := organizationpg.NewManagedSCIMMembershipWithdrawal(input, observed.ContributionActive, 31)
			if err != nil {
				t.Fatal(err)
			}
			p := &managedSCIMMembershipOwner{repository: store, input: input, update: update, projectionVersion: 31, denyFinal: scenario == "late-denial", grantBeforeFinal: scenario == "grant-before-final"}
			if scenario == "wrong-projection" {
				p.projectionVersion = 32
			}
			if scenario == "wrong-source-state" {
				other, err := organizationpg.NewManagedSCIMMembershipWithdrawal(input, false, 31)
				if err != nil {
					t.Fatal(err)
				}
				p.boundUpdate = &other
			}
			coordinator, command, plan := managedSCIMMembershipWork(t, f, p)
			if scenario == "late-grant" {
				seedGrant("resource-one", true)
			}
			got, err := executeDirectoryTeamNative(f.ctx, coordinator, command, plan)
			if scenario == "late-grant" || scenario == "grant-before-final" || scenario == "late-denial" || scenario == "wrong-projection" || scenario == "wrong-source-state" {
				if err == nil || got.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("stale absence or final denial committed", got.Outcome, err)
				}
			} else {
				if err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.Feature == nil || got.Feature.BeforeVersion != 31 || got.Feature.AfterVersion != 32 {
					t.Fatal("managed SCIM original projection lifecycle failed", got.Outcome, err)
				}
				wantOrganizationVersion := org.Version
				if scenario == "last-source" {
					wantOrganizationVersion++
				}
				if version, ok := p.effect.ManagedSCIMOrganizationVersion(); !ok || version != wantOrganizationVersion {
					t.Fatal("managed effect did not retain its exact organization successor", version, ok, wantOrganizationVersion)
				}
				replay, err := executeDirectoryTeamNative(f.ctx, coordinator, command, plan)
				if err != nil || !reflect.DeepEqual(got, replay) || p.applyCalls != 1 {
					t.Fatal("original SCIM receipt did not replay", err)
				}
			}
			after, err := store.ObserveManagedSCIMDirectoryMembership(f.ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "last-source" {
				if after.Member.Active || after.Member.Version != observed.Member.Version+1 || after.Member.AuthorizationVersion != observed.Member.AuthorizationVersion+1 {
					t.Fatal("last source did not revoke exact scoped membership")
				}
			} else if after.Member != observed.Member {
				t.Fatal("unrelated or rollback membership changed", scenario)
			}
			if scenario == "grant-before-final" && (after.ContributionVersion != 0 || after.ContributionActive) {
				t.Fatal("denied final source race escaped rollback")
			}
			var active bool
			var contributionVersion string
			if scenario == "last-source" || scenario == "other-source" || scenario == "late-denial" {
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT active,version::text FROM organization.directory_membership_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id='member' AND member_version=1 AND provider_id='provider-one' AND connection_id='connection-one'`, tenant, metadataOrganization).Scan(&active, &contributionVersion); err != nil {
					t.Fatal(err)
				}
				wantActive, wantVersion := scenario == "late-denial", "8"
				if wantActive {
					wantVersion = "7"
				}
				if active != wantActive || contributionVersion != wantVersion {
					t.Fatal("exact contribution was not atomically retired or restored", active, contributionVersion)
				}
			}
		})
	}
}

func TestManagedSCIMOrganizationVersionRejectsZeroAndLegacyEffects(t *testing.T) {
	if version, ok := (organizationpg.DirectoryMembershipEffect{}).ManagedSCIMOrganizationVersion(); ok || version != 0 {
		t.Fatal("zero effect exposed organization metadata", version, ok)
	}
	const tenant = "org-test-basic"
	f := newOrgFixture(t, organizationpg.CredentialAuthorityMigrationSource{Version: 305}, organizationpg.DirectoryMembershipMigrationSource{Version: 306})
	f.create(t, tenant)
	store, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	org, err := store.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: tenant, OrganizationID: metadataOrganization})
	if err != nil {
		t.Fatal(err)
	}
	source := organizationpg.DirectoryMembershipSource{TenantID: tenant, OrganizationID: metadataOrganization, UserID: "member", ProviderID: "provider-one", ConnectionID: "connection-one", ResourceID: "resource-one"}
	input := organizationpg.DirectoryMembershipInput{Source: source, ActorID: "directory-service", Organization: org, User: identity.User{TenantID: tenant, ID: "member", Status: identity.StatusActive, Version: 1}, Action: organizationpg.DirectoryMembershipGrant, MaximumMembers: 20, MaximumPerUser: 10}
	owner := &directoryMembershipWorkOwner{repository: store}
	coordinator, command, plan := directoryMembershipNativeWork(t, f, owner, input)
	got, err := executeDirectoryTeamNative(f.ctx, coordinator, command, plan)
	if err != nil || got.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("legacy source setup did not commit", got.Outcome, err)
	}
	if version, ok := owner.effect.ManagedSCIMOrganizationVersion(); ok || version != 0 {
		t.Fatal("legacy effect exposed managed organization metadata", version, ok)
	}
}
