//go:build integration

package postgres_test

import (
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestManagedSCIMMembershipDeactivationOriginalWork(t *testing.T) {
	patch := identity.FeatureOperation{Owner: "scim", OperationID: "identity.scim.user-patch", SchemaID: "identity.scim.user-patch.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, VersionPolicy: identity.FeatureVersionSequentialOrUnchanged}
	patchOwner := kernel.ContributorDescriptor{Owner: "scim/postgres", ContractID: "identity.scim", Version: 1}
	for _, scenario := range []string{"patch", "deactivation-with-delete", "withdrawal-with-patch", "withdrawal-field-with-patch", "deactivation-field-with-delete", "wrong-projection"} {
		t.Run(scenario, func(t *testing.T) {
			const tenant = "org-test-basic"
			f := newOrgFixture(t, organizationpg.CredentialAuthorityMigrationSource{Version: 305}, organizationpg.DirectoryMembershipMigrationSource{Version: 306})
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			store, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			source := organizationpg.DirectoryMembershipSource{TenantID: tenant, OrganizationID: metadataOrganization, UserID: "member", ProviderID: "provider-one", ConnectionID: "connection-one", ResourceID: "resource-one"}
			if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active) VALUES($1,$2,'member',1,'provider-one','connection-one','resource-one',7,true)`, tenant, metadataOrganization); err != nil {
				t.Fatal(err)
			}
			before, err := store.ObserveManagedSCIMDirectoryMembership(f.ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			org, err := store.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: tenant, OrganizationID: metadataOrganization})
			if err != nil {
				t.Fatal(err)
			}
			input := organizationpg.DirectoryMembershipInput{Source: source, ActorID: "directory-service", Organization: org, MemberVersion: before.Member.Version, MemberAuthorizationVersion: before.Member.AuthorizationVersion, ExpectedVersion: before.ContributionVersion, Action: organizationpg.DirectoryMembershipWithdraw}
			deactivation, err := organizationpg.NewManagedSCIMMembershipDeactivation(input, before.ContributionActive, 31)
			if err != nil {
				t.Fatal(err)
			}
			withdrawal, err := organizationpg.NewManagedSCIMMembershipWithdrawal(input, before.ContributionActive, 31)
			if err != nil {
				t.Fatal(err)
			}
			p := &managedSCIMMembershipOwner{repository: store, input: input, update: deactivation, projectionVersion: 31, operation: &patch, descriptor: &patchOwner}
			switch scenario {
			case "deactivation-with-delete":
				p.operation, p.descriptor = nil, nil
			case "withdrawal-with-patch":
				p.update = withdrawal
			case "withdrawal-field-with-patch":
				p.boundUpdate = &withdrawal
			case "deactivation-field-with-delete":
				p.operation, p.descriptor, p.update, p.boundUpdate = nil, nil, withdrawal, &deactivation
			case "wrong-projection":
				p.projectionVersion = 32
			}
			coordinator, command, plan := managedSCIMMembershipWork(t, f, p)
			got, err := executeDirectoryTeamNative(f.ctx, coordinator, command, plan)
			if scenario == "patch" {
				if err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.Feature == nil || got.Feature.Operation != patch || got.Feature.BeforeVersion != 31 || got.Feature.AfterVersion != 32 {
					t.Fatal("managed PATCH deactivation did not commit its original lifecycle", got.Outcome, err)
				}
				if version, ok := p.effect.ManagedSCIMOrganizationVersion(); !ok || version != org.Version+1 {
					t.Fatal("managed PATCH effect lost its exact organization successor", version, ok)
				}
				replay, err := executeDirectoryTeamNative(f.ctx, coordinator, command, plan)
				if err != nil || !reflect.DeepEqual(got, replay) || p.applyCalls != 1 {
					t.Fatal("managed PATCH replay repeated the membership effect", err, p.applyCalls)
				}
			} else if err == nil || got.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("cross-operation or digest substitution was not refused", got.Outcome, err)
			}
			after, err := store.ObserveManagedSCIMDirectoryMembership(f.ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "patch" {
				if after.Member.Active || after.Member.Version != before.Member.Version+1 || after.Member.AuthorizationVersion != before.Member.AuthorizationVersion+1 {
					t.Fatal("managed PATCH did not revoke its exact scoped membership")
				}
			} else if after != before {
				t.Fatal("refused substitution changed the grant or membership")
			}
			var grantActive bool
			var grantVersion string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT active,version::text FROM organization.directory_membership_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id='member' AND member_version=1 AND provider_id='provider-one' AND connection_id='connection-one' AND resource_id='resource-one'`, tenant, metadataOrganization).Scan(&grantActive, &grantVersion); err != nil {
				t.Fatal(err)
			}
			wantActive, wantVersion := true, "7"
			if scenario == "patch" {
				wantActive, wantVersion = false, "8"
			}
			if grantActive != wantActive || grantVersion != wantVersion {
				t.Fatal("exact source contribution was not atomically retired or preserved", grantActive, grantVersion)
			}
		})
	}
}
