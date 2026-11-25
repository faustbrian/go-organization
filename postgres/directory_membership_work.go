package postgres

import (
	"context"
	"fmt"
	"math"
	"strconv"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

// DirectoryMembershipLock retains the organization lock order in the invoking
// Work, not a reusable proof of source admission. Zero and foreign locks deny.
type DirectoryMembershipLock struct{ state *directoryMembershipLockState }

type directoryMembershipLockState struct {
	work    kernel.Work
	command identity.Command
	update  *directoryMembershipUpdateState
	members int64
}

func (DirectoryMembershipLock) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryMembershipLock(redacted)"))
}

// DirectoryMembershipEffect is an in-transaction projection for the final
// commit check, not a terminal receipt. It belongs to the original command
// and cannot be restored or used to infer the outcome of an ambiguous commit.
type DirectoryMembershipEffect struct {
	state *directoryMembershipEffectState
}

type directoryMembershipEffectState struct {
	work                kernel.Work
	command             identity.Command
	update              *directoryMembershipUpdateState
	member              organization.Member
	organizationVersion uint64
	contributionMember  uint64
}

func (DirectoryMembershipEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryMembershipEffect(redacted)"))
}

// LockDirectoryMembershipUpdate acquires the canonical tenant and organization
// locks without changing membership. Call after the source's directory status
// fence and before the source owner takes an organization SHARE or connection
// lock. Run only inside the admitted SSO User child's original Apply. The
// source owner must still fence its original connection and User projection
// before ApplyDirectoryMembershipUpdate is allowed to write.
func (r *Repository) LockDirectoryMembershipUpdate(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryMembershipUpdate) (DirectoryMembershipLock, error) {
	if r == nil || r.pool == nil || ctx == nil {
		return DirectoryMembershipLock{}, identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return DirectoryMembershipLock{}, err
	}
	if err := requireDirectoryMembershipBinding(w, owner, command, update); err != nil {
		return DirectoryMembershipLock{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()

	i, s := update.state.input, update.state.input.Source
	if err := lockMembershipTenant(ctx, w, s.TenantID); err != nil {
		return DirectoryMembershipLock{}, err
	}
	members, err := lockDirectoryMembershipOwner(ctx, w, s, i.Organization.Version, i.Organization.CredentialVersion)
	if err != nil {
		return DirectoryMembershipLock{}, err
	}
	if err := requireDirectoryMembershipDeadline(ctx, w, i); err != nil {
		return DirectoryMembershipLock{}, err
	}
	return DirectoryMembershipLock{state: &directoryMembershipLockState{work: w, command: command, update: update.state, members: members}}, nil
}

// ApplyDirectoryMembershipUpdate borrows the exact SSO User child's Work and
// changes only its source. A new directory-only member receives the ordinary
// Member role; local or replaced membership is never adopted as directory
// authority. Withdrawing the last live source removes that membership and
// advances its scoped authorization epoch. SSO must separately authorize and
// fence the provider, generation and source evidence, propagate errors, and
// pass the returned effect to RequireDirectoryMembershipEffect before commit.
func (r *Repository) ApplyDirectoryMembershipUpdate(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryMembershipUpdate, locked DirectoryMembershipLock) (DirectoryMembershipEffect, error) {
	if r == nil || r.pool == nil || ctx == nil || locked.state == nil || locked.state.work != w || locked.state.command != command || locked.state.update != update.state {
		return DirectoryMembershipEffect{}, identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return DirectoryMembershipEffect{}, err
	}
	if err := requireDirectoryMembershipBinding(w, owner, command, update); err != nil {
		return DirectoryMembershipEffect{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	i, s := update.state.input, update.state.input.Source
	if i.Action == DirectoryMembershipGrant {
		if err := w.RequireActiveTargetUser(ctx, owner, i.User); err != nil {
			return DirectoryMembershipEffect{}, err
		}
	}
	member, err := readMember(ctx, w, s.TenantID, s.OrganizationID, s.UserID)
	if err != nil {
		return DirectoryMembershipEffect{}, err
	}
	if member.Version != i.MemberVersion || member.AuthorizationVersion != i.MemberAuthorizationVersion {
		return DirectoryMembershipEffect{}, identity.ForbiddenError{}
	}
	scoped, err := OrganizationAuthorityScope(s.TenantID, s.OrganizationID, s.UserID)
	if err != nil {
		return DirectoryMembershipEffect{}, err
	}
	p := directoryMembershipEffectState{work: w, command: command, update: update.state, member: member, organizationVersion: i.Organization.Version, contributionMember: member.Version}
	if member.Version == 0 {
		if err := r.addDirectoryMember(ctx, w, scoped, &p, locked.state.members); err != nil {
			return DirectoryMembershipEffect{}, err
		}
	} else {
		if err := r.requireCurrentDirectoryMember(ctx, w, scoped, i, member); err != nil {
			return DirectoryMembershipEffect{}, err
		}
	}
	if err := persistDirectoryMembershipGrant(ctx, w, update, p.contributionMember); err != nil {
		return DirectoryMembershipEffect{}, err
	}
	if i.Action == DirectoryMembershipWithdraw {
		remaining, err := hasDirectoryMembershipGrant(ctx, w, s, member.Version)
		if err != nil {
			return DirectoryMembershipEffect{}, err
		}
		if !remaining {
			if err := r.removeDirectoryMember(ctx, w, scoped, &p); err != nil {
				return DirectoryMembershipEffect{}, err
			}
		}
	}
	if err := requireDirectoryMembershipDeadline(ctx, w, i); err != nil {
		return DirectoryMembershipEffect{}, err
	}
	return DirectoryMembershipEffect{state: &p}, nil
}

const lockDirectoryMembershipOwnerSQL = `SELECT version::text,credential_version::text,member_count,owner_count FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 AND state='active' FOR NO KEY UPDATE`

func lockDirectoryMembershipOwner(ctx context.Context, w kernel.Work, s DirectoryMembershipSource, orgVersion, credentialVersion uint64) (int64, error) {
	var version, credential string
	var members, owners int64
	rows, err := w.Query(ctx, lockDirectoryMembershipOwnerSQL, string(s.TenantID), string(s.OrganizationID))
	if err := one(rows, err, &version, &credential, &members, &owners); err != nil {
		return 0, err
	}
	if version != strconv.FormatUint(orgVersion, 10) || credential != strconv.FormatUint(credentialVersion, 10) {
		return 0, identity.ForbiddenError{}
	}
	if members < 1 || owners < 1 || owners > members {
		return 0, identity.UnavailableError{}
	}
	return members, nil
}

func (r *Repository) addDirectoryMember(ctx context.Context, w kernel.Work, scoped authority.AuthorityScope, p *directoryMembershipEffectState, members int64) error {
	i, s := p.update.input, p.update.input.Source
	if i.Action != DirectoryMembershipGrant {
		return identity.ForbiddenError{}
	}
	if err := requireMembershipCapacity(ctx, w, s.TenantID, s.UserID, members, i.MaximumMembers, i.MaximumPerUser); err != nil {
		return err
	}
	next, err := authority.InitializeAuthority(ctx, w, scoped, r.maximum)
	if err != nil {
		return authorityError(err)
	}
	if err := advanceMembershipOrganization(ctx, w, s.TenantID, s.OrganizationID, p.organizationVersion, 1, 0); err != nil {
		return err
	}
	if err := persistAddedMember(ctx, w, s.TenantID, s.OrganizationID, s.UserID, organization.RoleMember, 0, next.Version); err != nil {
		return err
	}
	p.organizationVersion++
	p.member.Role, p.member.Active, p.member.Version, p.member.AuthorizationVersion = organization.RoleMember, true, 1, next.Version
	p.contributionMember = p.member.Version
	return nil
}

func (r *Repository) requireCurrentDirectoryMember(ctx context.Context, w kernel.Work, scoped authority.AuthorityScope, i DirectoryMembershipInput, member organization.Member) error {
	if !member.Active || member.Role != organization.RoleMember {
		return identity.ForbiddenError{}
	}
	if err := authority.RequireAuthority(ctx, w, scoped, member.AuthorizationVersion, r.maximum); err != nil {
		return authorityError(err)
	}
	// Existing membership is proved directory-owned only by a source bound to
	// this row's exact version. Local writes that replace the member or change
	// its role advance that version and are not adopted on directory input.
	active, err := hasDirectoryMembershipGrant(ctx, w, i.Source, member.Version)
	if err != nil {
		return err
	}
	if !active {
		return identity.ForbiddenError{}
	}
	return nil
}

func (r *Repository) removeDirectoryMember(ctx context.Context, w kernel.Work, scoped authority.AuthorityScope, p *directoryMembershipEffectState) error {
	s, member := p.update.input.Source, p.member
	if member.Version == math.MaxUint64 {
		return identity.ConflictError{}
	}
	next, err := authority.AdvanceAuthority(ctx, w, scoped, member.AuthorizationVersion, r.maximum)
	if err != nil {
		return authorityError(err)
	}
	if err := advanceMembershipOrganization(ctx, w, s.TenantID, s.OrganizationID, p.organizationVersion, -1, 0); err != nil {
		return err
	}
	if err := persistRemovedMember(ctx, w, s.TenantID, s.OrganizationID, s.UserID, member.Version, next.Version); err != nil {
		return err
	}
	p.organizationVersion++
	p.member.Active, p.member.Version, p.member.AuthorizationVersion = false, member.Version+1, next.Version
	return nil
}

func requireDirectoryMembershipDeadline(ctx context.Context, w kernel.Work, i DirectoryMembershipInput) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if i.Organization.Validate(i.Source.organizationQuery(), now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// RequireDirectoryMembershipEffect rechecks the provisional contribution,
// member, authority epochs and unchanged original deadline in the owning
// participant's final phase. A zero effect or another command's effect denies.
// This check does not own provider or source evidence, audit, or recovery.
func (r *Repository) RequireDirectoryMembershipEffect(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryMembershipUpdate, effect DirectoryMembershipEffect) error {
	if r == nil || r.pool == nil || ctx == nil || effect.state == nil || effect.state.work != w || effect.state.command != command || effect.state.update != update.state {
		return identity.ForbiddenError{}
	}
	if err := requireDirectoryMembershipBinding(w, owner, command, update); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	i, p := update.state.input, effect.state
	s := i.Source
	if i.Action == DirectoryMembershipGrant {
		if err := w.RequireActiveTargetUser(ctx, owner, i.User); err != nil {
			return err
		}
	}
	if _, err := lockDirectoryMembershipOwner(ctx, w, s, p.organizationVersion, i.Organization.CredentialVersion); err != nil {
		return err
	}
	member, err := readMember(ctx, w, s.TenantID, s.OrganizationID, s.UserID)
	if err != nil {
		return err
	}
	if member != p.member {
		return identity.ForbiddenError{}
	}
	scoped, err := OrganizationAuthorityScope(s.TenantID, s.OrganizationID, s.UserID)
	if err != nil {
		return err
	}
	if err := authority.RequireAuthority(ctx, w, scoped, member.AuthorizationVersion, r.maximum); err != nil {
		return authorityError(err)
	}
	if err := requireDirectoryMembershipGrant(ctx, w, update, p.contributionMember); err != nil {
		return err
	}
	remaining, err := hasDirectoryMembershipGrant(ctx, w, s, p.contributionMember)
	if err != nil {
		return err
	}
	if member.Active != remaining {
		return identity.ForbiddenError{}
	}
	return requireDirectoryMembershipDeadline(ctx, w, i)
}

// RequireDirectoryMembershipSourceOwner lets the source owner's final check
// accept exactly the same Work's own organization successor. The source must
// supply its original owner observation and exact configured User binding.
// This substitutes only the version produced by the effect, without exporting
// an amended observation, accepting a guessed successor or renewing freshness.
// The caller still checks the remaining original source and membership facts.
func (r *Repository) RequireDirectoryMembershipSourceOwner(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, source DirectoryMembershipSource, original organization.CredentialAuthorityObservation, effect DirectoryMembershipEffect) error {
	if r == nil || r.pool == nil || ctx == nil || effect.state == nil || effect.state.work != w || effect.state.command != command {
		return identity.ForbiddenError{}
	}
	p := effect.state
	i := p.update.input
	if source != i.Source || original.TenantID != source.TenantID || original.OrganizationID != source.OrganizationID ||
		original.Version != i.Organization.Version || original.CredentialVersion != i.Organization.CredentialVersion {
		return identity.ForbiddenError{}
	}
	if err := requireDirectoryMembershipBinding(w, owner, command, DirectoryMembershipUpdate{state: p.update}); err != nil {
		return err
	}
	original.Version = p.organizationVersion
	return r.RequireCredentialAuthority(ctx, w, owner, original)
}
