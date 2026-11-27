package postgres

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

type managedSCIMMembershipWithdrawal struct {
	contributionActive bool
	projectionVersion  uint64
	deactivation       bool
}

// ManagedSCIMOrganizationVersion returns the exact provisional organization
// version written or retained by this managed SCIM effect. Zero and legacy SSO
// effects return zero, false. The result is metadata, not proof of commit,
// freshness or authority. A consumer may use it only after the kernel confirms
// this same original command, and must independently compare current authority
// under the original, unextended admission deadline.
func (e DirectoryMembershipEffect) ManagedSCIMOrganizationVersion() (uint64, bool) {
	if e.state == nil || e.state.update == nil || e.state.update.managedSCIM == nil || e.state.organizationVersion == 0 {
		return 0, false
	}
	return e.state.organizationVersion, true
}

// NewManagedSCIMMembershipWithdrawal freezes the exact current-incarnation
// source expectation for a managed SCIM UserDelete in its original Work. Zero
// ExpectedVersion means current-incarnation absence, not historical absence;
// nonzero with contributionActive=false means a retained retired source. Both
// are locked no-ops, not permission to adopt local or replaced membership.
//
// The original command binds Field and the SCIM ResourceID, service actor and
// native UserID. Its lifecycle must advance expectedProjectionVersion by one,
// independently of contribution versions. This pure constructor authenticates
// nothing. The source owner must fence directory authority before the canonical
// organization lock, then its connection, mapping and original User projection.
func NewManagedSCIMMembershipWithdrawal(i DirectoryMembershipInput, contributionActive bool, expectedProjectionVersion uint64) (DirectoryMembershipUpdate, error) {
	return newManagedSCIMMembershipWithdrawal(i, contributionActive, expectedProjectionVersion, false)
}

// NewManagedSCIMMembershipDeactivation freezes the same exact-current-source
// withdrawal for an advancing managed User PATCH which makes the projection
// inactive. Its field commitment is distinct from UserDelete. The original
// native PATCH Work must bind the source, subject, actor and exact projection
// successor. The caller owns validating and applying the inactive projection
// in that same Work. Construction neither establishes authority nor writes.
func NewManagedSCIMMembershipDeactivation(i DirectoryMembershipInput, contributionActive bool, expectedProjectionVersion uint64) (DirectoryMembershipUpdate, error) {
	return newManagedSCIMMembershipWithdrawal(i, contributionActive, expectedProjectionVersion, true)
}

func newManagedSCIMMembershipWithdrawal(i DirectoryMembershipInput, contributionActive bool, expectedProjectionVersion uint64, deactivation bool) (DirectoryMembershipUpdate, error) {
	if !i.Source.validate() || !scope(string(i.ActorID)) || i.Action != DirectoryMembershipWithdraw || i.User != (identity.User{}) ||
		i.Organization.Validate(i.Source.organizationQuery(), time.Now().UTC()) != nil ||
		(i.MemberVersion == 0) != (i.MemberAuthorizationVersion == 0) ||
		(i.MemberVersion == 0 && i.ExpectedVersion != 0) ||
		(contributionActive && (i.ExpectedVersion == 0 || i.ExpectedVersion == math.MaxUint64)) ||
		expectedProjectionVersion == 0 || expectedProjectionVersion == math.MaxUint64 {
		return DirectoryMembershipUpdate{}, organization.ErrInvalidInput
	}
	wire, err := json.Marshal(struct {
		Input              DirectoryMembershipInput
		ContributionActive bool
		ProjectionVersion  uint64
	}{i, contributionActive, expectedProjectionVersion})
	if err != nil {
		return DirectoryMembershipUpdate{}, organization.ErrInvalidInput
	}
	domain := "organization.directory-membership.managed-scim-withdrawal.v1"
	if deactivation {
		domain = "organization.directory-membership.managed-scim-deactivation.v1"
	}
	return DirectoryMembershipUpdate{state: &directoryMembershipUpdateState{
		input: i, recordID: string(i.Source.ResourceID),
		digest:      directoryMembershipDigest(domain, wire),
		managedSCIM: &managedSCIMMembershipWithdrawal{contributionActive: contributionActive, projectionVersion: expectedProjectionVersion, deactivation: deactivation},
	}}, nil
}

func (m managedSCIMMembershipWithdrawal) registration() kernel.FeatureRegistration {
	op := identity.FeatureOperation{Owner: "scim", OperationID: "identity.scim.user-delete", SchemaID: "identity.scim.user-delete.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential}
	descriptor := kernel.ContributorDescriptor{Owner: "scim/postgres", ContractID: "identity.scim.managed", Version: 1}
	if m.deactivation {
		op.OperationID, op.SchemaID = "identity.scim.user-patch", "identity.scim.user-patch.native-v1"
		op.SubjectRequirement, op.VersionPolicy = 0, identity.FeatureVersionSequentialOrUnchanged
		descriptor.ContractID = "identity.scim"
	}
	return kernel.FeatureRegistration{Contributor: descriptor, Operation: op}
}

func (r *Repository) applyManagedSCIMMembershipWithdrawal(ctx context.Context, w kernel.Work, scoped authority.AuthorityScope, p *directoryMembershipEffectState) (DirectoryMembershipEffect, error) {
	update := DirectoryMembershipUpdate{state: p.update}
	i, member := p.update.input, p.member
	if member.Version != 0 {
		if err := authority.RequireAuthority(ctx, w, scoped, member.AuthorizationVersion, r.maximum); err != nil {
			return DirectoryMembershipEffect{}, authorityError(err)
		}
	}
	if err := requireManagedSCIMMembershipGrant(ctx, w, update, member.Version, i.ExpectedVersion, p.update.managedSCIM.contributionActive); err != nil {
		return DirectoryMembershipEffect{}, err
	}
	if p.update.managedSCIM.contributionActive {
		if err := persistDirectoryMembershipGrant(ctx, w, update, member.Version); err != nil {
			return DirectoryMembershipEffect{}, err
		}
		// Only a live ordinary member still owned by this exact incarnation can
		// lose effective membership. Local role/replacement authority is not
		// acquired merely because an old directory source exists.
		if member.Active && member.Role == organization.RoleMember {
			remaining, err := hasDirectoryMembershipGrant(ctx, w, i.Source, member.Version)
			if err != nil {
				return DirectoryMembershipEffect{}, err
			}
			if !remaining {
				if err := r.removeDirectoryMember(ctx, w, scoped, p); err != nil {
					return DirectoryMembershipEffect{}, err
				}
			}
		}
	}
	if err := requireDirectoryMembershipDeadline(ctx, w, i); err != nil {
		return DirectoryMembershipEffect{}, err
	}
	return DirectoryMembershipEffect{state: p}, nil
}

// Reuse the exact current-incarnation primary-key probe. The canonical owner
// locks retained by the Work serialize legitimate membership/grant writers;
// absence is checked again at final commit, never inferred from preparation.
func requireManagedSCIMMembershipGrant(ctx context.Context, w kernel.Work, update DirectoryMembershipUpdate, memberVersion, expectedVersion uint64, expectedActive bool) error {
	s := update.state.input.Source
	rows, err := w.Query(ctx, requireDirectoryMembershipGrantSQL, string(s.TenantID), string(s.OrganizationID), string(s.UserID), strconv.FormatUint(memberVersion, 10), string(s.ProviderID), string(s.ConnectionID))
	if err != nil {
		return err
	}
	defer rows.Close()
	var resource, version string
	var active bool
	found := rows.Next()
	if found {
		if err := rows.Scan(&resource, &version, &active); err != nil {
			return err
		}
		if rows.Next() {
			return identity.UnavailableError{}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	exactSource := found && resource == string(s.ResourceID)
	if expectedVersion == 0 {
		if exactSource || expectedActive {
			return identity.ForbiddenError{}
		}
		return nil
	}
	if !exactSource || version != strconv.FormatUint(expectedVersion, 10) || active != expectedActive {
		return identity.ForbiddenError{}
	}
	return nil
}
