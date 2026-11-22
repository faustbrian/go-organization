package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

const providerJITMembershipField = "organization.sso-provider-jit-membership"

// ProviderJITMembershipInput selects an ordinary membership for the identity
// owner's just-created enterprise user. Owner must be the original owner-only
// observation, and capacities must come from the trusted composition's current
// configuration. This value grants no authentication or membership authority.
type ProviderJITMembershipInput struct {
	Owner                          organization.CredentialAuthorityObservation
	UserID                         identity.UserID
	MaximumMembers, MaximumPerUser uint64
}

// ProviderJITMembership is immutable command intent, not an admission or a
// renewable observation. Its zero value is invalid. Apply requires identity's
// actual newly-created-user proof from the exact invoking Work.
type ProviderJITMembership struct{ state *providerJITMembershipState }

type providerJITMembershipState struct {
	input       ProviderJITMembershipInput
	fingerprint [32]byte
}

// NewProviderJITMembership snapshots the exact original owner, target and
// configured capacities. It rejects overflow, member observations and capacities
// outside the existing membership contributor's supported configuration bounds.
// Freshness is checked against primary database time again by Apply.
func NewProviderJITMembership(input ProviderJITMembershipInput) (ProviderJITMembership, error) {
	owner := input.Owner
	query := organization.CredentialAuthorityQuery{TenantID: owner.TenantID, OrganizationID: owner.OrganizationID}
	if owner.Validate(query, owner.VerifiedAt) != nil || owner.Version == math.MaxUint64 ||
		!scope(string(input.UserID)) || input.MaximumMembers < 1 || input.MaximumMembers > 100000 ||
		input.MaximumPerUser < 1 || input.MaximumPerUser > 1000 {
		return ProviderJITMembership{}, organization.ErrInvalidInput
	}
	wire, err := json.Marshal(input)
	if err != nil {
		return ProviderJITMembership{}, organization.ErrInvalidInput
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("organization.provider-jit-membership.v1\x00"))
	_, _ = hash.Write(wire)
	var fingerprint [32]byte
	copy(fingerprint[:], hash.Sum(nil))
	return ProviderJITMembership{&providerJITMembershipState{input, fingerprint}}, nil
}

// ExpectedOrganizationVersion is the exact successor produced by Apply, or
// zero for an invalid preparation. It predicts no other organization effect.
func (p ProviderJITMembership) ExpectedOrganizationVersion() uint64 {
	if p.state == nil {
		return 0
	}
	return p.state.input.Owner.Version + 1
}

// Field returns detached command data binding the complete membership intent.
// The digest does not disclose the owner/target or authenticate their authority.
func (p ProviderJITMembership) Field() (identity.FeatureField, error) {
	if p.state == nil {
		return identity.FeatureField{}, organization.ErrInvalidInput
	}
	return identity.FeatureField{Name: providerJITMembershipField, Value: identity.FeatureValue{
		Kind: identity.FeatureBytes, Bytes: slices.Clone(p.state.fingerprint[:]),
	}}, nil
}

// Format redacts original owner, identity and capacity data.
func (ProviderJITMembership) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ProviderJITMembership(redacted)"))
}

// ApplyProviderJITMembership adds only identity's actual newly-created active
// enterprise user, never an existing account or a removed membership. It borrows
// the registered callback's original synchronous Work and command; call after
// identity creation and before session organization fences. The callback must
// propagate errors, retain its original provider/flow commit fences and recover
// through identity's sole coordinator. No transaction, journal or session is
// created here. Tenant serialization retains the existing cardinality contract.
func (r *Repository) ApplyProviderJITMembership(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, prepared ProviderJITMembership) error {
	if r == nil || r.pool == nil || ctx == nil || prepared.state == nil {
		return identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	p := prepared.state
	feature, _ := command.Feature()
	if !matchesProviderJITMembershipField(feature.Fields, p.fingerprint) {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	created, err := w.SSOOIDCJITUser(ctx, owner, command)
	if err != nil {
		return err
	}
	input := p.input
	if created.Validate(input.Owner.TenantID) != nil || created.ID != input.UserID || created.Status != identity.StatusActive || created.Version != 1 {
		return identity.ForbiddenError{}
	}
	query := organization.CredentialAuthorityQuery{TenantID: input.Owner.TenantID, OrganizationID: input.Owner.OrganizationID}
	if input.Owner.Validate(query, time.Now().UTC()) != nil {
		return identity.ForbiddenError{}
	}
	if err := lockMembershipTenant(ctx, w, input.Owner.TenantID); err != nil {
		return err
	}
	if err := lockProviderJITOrganization(ctx, w, input); err != nil {
		return err
	}
	target, err := readMember(ctx, w, input.Owner.TenantID, input.Owner.OrganizationID, input.UserID)
	if err != nil {
		return err
	}
	if target.Version != 0 {
		return identity.ForbiddenError{}
	}
	scope, err := OrganizationAuthorityScope(input.Owner.TenantID, input.Owner.OrganizationID, input.UserID)
	if err != nil {
		return err
	}
	projection, err := authority.InitializeAuthority(ctx, w, scope, r.maximum)
	if err != nil {
		return authorityError(err)
	}
	if err := advanceMembershipOrganization(ctx, w, input.Owner.TenantID, input.Owner.OrganizationID, input.Owner.Version, 1, 0); err != nil {
		return err
	}
	if err := persistAddedMember(ctx, w, input.Owner.TenantID, input.Owner.OrganizationID, input.UserID, organization.RoleMember, 0, projection.Version); err != nil {
		return err
	}
	// Sample after every lock wait and write, including authority initialization;
	// an expired original observation must abort the whole borrowed transaction.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if input.Owner.Validate(query, now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func matchesProviderJITMembershipField(fields []identity.FeatureField, fingerprint [32]byte) bool {
	for _, field := range fields {
		if field.Name == providerJITMembershipField {
			return field.Value.Kind == identity.FeatureBytes && bytes.Equal(field.Value.Bytes, fingerprint[:])
		}
	}
	return false
}

func lockProviderJITOrganization(ctx context.Context, w kernel.Work, input ProviderJITMembershipInput) error {
	owner := input.Owner
	var version, credential string
	var members, owners int64
	rows, err := w.Query(ctx, `SELECT version::text,credential_version::text,member_count,owner_count
FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 AND state='active' FOR NO KEY UPDATE`, string(owner.TenantID), string(owner.OrganizationID))
	if err := one(rows, err, &version, &credential, &members, &owners); err != nil {
		return err
	}
	if version != strconv.FormatUint(owner.Version, 10) || credential != strconv.FormatUint(owner.CredentialVersion, 10) {
		return identity.ForbiddenError{}
	}
	if members < 1 || owners < 1 || owners > members {
		return identity.UnavailableError{}
	}
	return requireMembershipCapacity(ctx, w, owner.TenantID, input.UserID, members, input.MaximumMembers, input.MaximumPerUser)
}
