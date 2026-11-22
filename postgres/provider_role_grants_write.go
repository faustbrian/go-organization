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

const providerRoleGrantField = "organization.sso-provider-role-replacement"

const providerRoleGrantSetSQL = `SELECT organization_member_version::text,mapping_version::text,provider_generation::text,flow_started_at,assertion_issued_at,to_json(role_ids)::text
FROM organization.provider_role_grants WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND provider_id=$4`

// ProviderRoleGrantUpdate binds one exact managed replacement to the original
// active member observation and the selected provider source generation. Zero
// is invalid. It is not authentication, a renewable lease, or a durable result.
type ProviderRoleGrantUpdate struct{ state *providerRoleGrantUpdateState }

type providerRoleGrantUpdateState struct {
	grants                      organization.ProviderRoleGrantSet
	member                      organization.CredentialAuthorityObservation
	generation                  uint64
	expectedOrganizationVersion uint64
	fingerprint                 [32]byte
}

// NewProviderRoleGrantUpdate snapshots a configured, authoritative role set and
// the original member observation. The federation owner must supply these from
// its validated assertion and original prepared callback, not from its client.
// expectedOrganizationVersion is the original aggregate version for no policy
// change, or its exact successor. Apply independently verifies that prediction.
func NewProviderRoleGrantUpdate(grants organization.ProviderRoleGrantSet, member organization.CredentialAuthorityObservation, generation, expectedOrganizationVersion uint64) (ProviderRoleGrantUpdate, error) {
	input, valid := grants.Value()
	if !valid || generation == 0 || member.Actor.Version != input.MemberVersion ||
		member.Validate(providerRoleMemberQuery(input.Scope), member.VerifiedAt) != nil {
		return ProviderRoleGrantUpdate{}, organization.ErrInvalidInput
	}
	if expectedOrganizationVersion != member.Version &&
		(member.Version == math.MaxUint64 || expectedOrganizationVersion != member.Version+1) {
		return ProviderRoleGrantUpdate{}, organization.ErrInvalidInput
	}
	wire, err := json.Marshal(struct {
		Grants                      organization.ProviderRoleGrantInput
		Member                      organization.CredentialAuthorityObservation
		ProviderGeneration          uint64
		ExpectedOrganizationVersion uint64
	}{input, member, generation, expectedOrganizationVersion})
	if err != nil {
		return ProviderRoleGrantUpdate{}, organization.ErrInvalidInput
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("organization.provider-role-replacement.v1\x00"))
	_, _ = hash.Write(wire)
	var fingerprint [32]byte
	copy(fingerprint[:], hash.Sum(nil))
	return ProviderRoleGrantUpdate{&providerRoleGrantUpdateState{grants, member, generation, expectedOrganizationVersion, fingerprint}}, nil
}

// PrepareProviderRoleGrantUpdate predicts the post-Apply aggregate version from
// the exact retained provider grant. It does not renew the supplied observation
// or admit a replacement: Apply rechecks current state and replacement ordering
// inside the original Work. Any failure returns a zero update.
func (r *Repository) PrepareProviderRoleGrantUpdate(ctx context.Context, grants organization.ProviderRoleGrantSet, member organization.CredentialAuthorityObservation, generation uint64) (ProviderRoleGrantUpdate, error) {
	if r == nil || r.pool == nil || ctx == nil {
		return ProviderRoleGrantUpdate{}, organization.ErrInvalidInput
	}
	if _, err := NewProviderRoleGrantUpdate(grants, member, generation, member.Version); err != nil {
		return ProviderRoleGrantUpdate{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	input, _ := grants.Value()
	scope := input.Scope
	rows, err := r.pool.Raw().Query(ctx, providerRoleGrantSetSQL,
		string(scope.TenantID), string(scope.OrganizationID), string(scope.UserID), string(scope.ProviderID))
	previous, oldGeneration, exists, err := scanProviderRoleGrantSet(rows, err, scope)
	if err != nil {
		return ProviderRoleGrantUpdate{}, storageError(ctx, err)
	}
	expected, err := providerRoleOrganizationVersion(member.Version, input, generation, previous, oldGeneration, exists)
	if err != nil {
		return ProviderRoleGrantUpdate{}, err
	}
	return NewProviderRoleGrantUpdate(grants, member, generation, expected)
}

// ExpectedOrganizationVersion returns the predicted aggregate version bound to
// this exact update, or zero for an invalid update. It grants no authority.
func (u ProviderRoleGrantUpdate) ExpectedOrganizationVersion() uint64 {
	if u.state == nil {
		return 0
	}
	return u.state.expectedOrganizationVersion
}

func providerRoleMemberQuery(scope organization.ProviderRoleGrantScope) organization.CredentialAuthorityQuery {
	return organization.CredentialAuthorityQuery{TenantID: scope.TenantID, OrganizationID: scope.OrganizationID, ActorID: scope.UserID}
}

// Field returns the detached operation field the federation owner must include
// in the exact callback Apply command. The digest binds the complete write but
// does not disclose role IDs, assert proof freshness, or authorize application.
func (u ProviderRoleGrantUpdate) Field() (identity.FeatureField, error) {
	if u.state == nil {
		return identity.FeatureField{}, organization.ErrInvalidInput
	}
	return identity.FeatureField{Name: providerRoleGrantField, Value: identity.FeatureValue{
		Kind: identity.FeatureBytes, Bytes: slices.Clone(u.state.fingerprint[:]),
	}}, nil
}

// Format redacts provider, member, role and original authority data.
func (ProviderRoleGrantUpdate) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ProviderRoleGrantUpdate(redacted)"))
}

// ApplyProviderRoleGrantUpdate replaces only the exact provider's role grants
// inside the registered enterprise callback's existing Work. Call once after
// session row locks and before the first organization session fence. The SSO
// owner must propagate errors, fence the verified provider/flow at commit, and
// recover through the original coordinator. No transaction or session is
// created here, and application-owned direct/team assignments are never changed.
func (r *Repository) ApplyProviderRoleGrantUpdate(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update ProviderRoleGrantUpdate) error {
	if r == nil || r.pool == nil || ctx == nil || update.state == nil {
		return identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	u := update.state
	input, _ := u.grants.Value()
	feature, _ := command.Feature()
	if !matchesProviderRoleGrantField(feature.Fields, u.fingerprint) {
		return identity.ForbiddenError{}
	}
	account, err := kernel.SSOOIDCSigninAccount(command)
	if err != nil || account.Account.TenantID != input.Scope.TenantID || account.Account.UserID != input.Scope.UserID {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	if _, err := w.RequireSSOOIDCSigninProviderAccount(ctx, owner, command); err != nil {
		return err
	}
	if err := r.lockProviderRoleMember(ctx, w, owner, u, input); err != nil {
		return err
	}
	if err := requireProviderRoleSource(ctx, w, input, u.generation); err != nil {
		return err
	}
	return r.persistProviderRoleGrantUpdate(ctx, w, u, input)
}

func matchesProviderRoleGrantField(fields []identity.FeatureField, digest [32]byte) bool {
	for _, field := range fields {
		if field.Name == providerRoleGrantField {
			return field.Value.Kind == identity.FeatureBytes && bytes.Equal(field.Value.Bytes, digest[:])
		}
	}
	return false
}

func (r *Repository) lockProviderRoleMember(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, update *providerRoleGrantUpdateState, input organization.ProviderRoleGrantInput) error {
	expected := update.member
	if update.expectedOrganizationVersion == expected.Version {
		// A no-change prediction retains the normal shared owner fence. Apply
		// aborts on a changed projection rather than upgrading this lock.
		ownerOnly := expected
		ownerOnly.Actor = organization.Member{}
		if err := r.RequireCredentialAuthority(ctx, w, owner, ownerOnly); err != nil {
			return err
		}
	} else if err := r.lockProviderRoleOrganizationChange(ctx, w, owner, expected, input.Scope); err != nil {
		return err
	}
	scope := input.Scope
	member, err := readMember(ctx, w, scope.TenantID, scope.OrganizationID, scope.UserID)
	if err != nil {
		return err
	}
	if member != expected.Actor {
		return identity.ForbiddenError{}
	}
	return nil
}

func (r *Repository) lockProviderRoleOrganizationChange(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, expected organization.CredentialAuthorityObservation, scope organization.ProviderRoleGrantScope) error {
	// Take the write-compatible aggregate lock before membership. The callback's
	// browser actor is not the resolved human, so this is an owner-only fence.
	if expected.Validate(providerRoleMemberQuery(scope), time.Now().UTC()) != nil {
		return identity.ForbiddenError{}
	}
	binding, _, _, err := w.FeatureScope(owner)
	if err != nil || binding.TenantID != expected.TenantID {
		return identity.ForbiddenError{}
	}
	var version, credential string
	rows, err := w.Query(ctx, `SELECT version::text,credential_version::text
FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 AND state='active' FOR NO KEY UPDATE`,
		string(expected.TenantID), string(expected.OrganizationID))
	if err := one(rows, err, &version, &credential); err != nil {
		return err
	}
	if version != strconv.FormatUint(expected.Version, 10) || credential != strconv.FormatUint(expected.CredentialVersion, 10) {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if expected.Validate(providerRoleMemberQuery(scope), now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func requireProviderRoleSource(ctx context.Context, w kernel.Work, input organization.ProviderRoleGrantInput, generation uint64) error {
	scope := input.Scope
	// Hold only the source key. The provider owner locks its actual provider
	// row at commit, and its trigger changes non-key source columns. Holding
	// SHARE here would reverse that lock order against a concurrent disable.
	rows, err := w.Query(ctx, `SELECT generation::text,mapping_version::text FROM organization.provider_role_sources
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND active FOR KEY SHARE`, string(scope.TenantID), string(scope.OrganizationID), string(scope.ProviderID))
	var current, mapping string
	if err := one(rows, err, &current, &mapping); err != nil {
		return err
	}
	if current != strconv.FormatUint(generation, 10) || mapping != strconv.FormatUint(input.MappingVersion, 10) {
		return identity.ForbiddenError{}
	}
	return nil
}

type providerRoleGrantRows interface {
	Close()
	Next() bool
	Scan(...any) error
	Err() error
}

func readProviderRoleGrantSet(ctx context.Context, w kernel.Work, scope organization.ProviderRoleGrantScope) (organization.ProviderRoleGrantSet, uint64, bool, error) {
	rows, err := w.Query(ctx, providerRoleGrantSetSQL,
		string(scope.TenantID), string(scope.OrganizationID), string(scope.UserID), string(scope.ProviderID))
	return scanProviderRoleGrantSet(rows, err, scope)
}

func scanProviderRoleGrantSet(rows providerRoleGrantRows, err error, scope organization.ProviderRoleGrantScope) (organization.ProviderRoleGrantSet, uint64, bool, error) {
	if err != nil {
		return organization.ProviderRoleGrantSet{}, 0, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return organization.ProviderRoleGrantSet{}, 0, false, rows.Err()
	}
	input := organization.ProviderRoleGrantInput{Scope: scope}
	var member, mapping, generation, roleJSON string
	if err := rows.Scan(&member, &mapping, &generation, &input.OriginalFlowStartedAt, &input.AssertedAt, &roleJSON); err != nil {
		return organization.ProviderRoleGrantSet{}, 0, false, err
	}
	if rows.Next() {
		return organization.ProviderRoleGrantSet{}, 0, false, identity.UnavailableError{}
	}
	if err := rows.Err(); err != nil {
		return organization.ProviderRoleGrantSet{}, 0, false, err
	}
	if len(roleJSON) > 32768 || json.Unmarshal([]byte(roleJSON), &input.RoleIDs) != nil {
		return organization.ProviderRoleGrantSet{}, 0, false, identity.UnavailableError{}
	}
	input.MemberVersion, err = positive(member)
	if err != nil {
		return organization.ProviderRoleGrantSet{}, 0, false, err
	}
	input.MappingVersion, err = positive(mapping)
	if err != nil {
		return organization.ProviderRoleGrantSet{}, 0, false, err
	}
	gen, err := positive(generation)
	if err != nil {
		return organization.ProviderRoleGrantSet{}, 0, false, err
	}
	set, err := organization.NewProviderRoleGrantSet(input)
	if err != nil {
		return organization.ProviderRoleGrantSet{}, 0, false, identity.UnavailableError{}
	}
	return set, gen, true, nil
}

func (r *Repository) persistProviderRoleGrantUpdate(ctx context.Context, w kernel.Work, update *providerRoleGrantUpdateState, input organization.ProviderRoleGrantInput) error {
	scope := input.Scope
	tenant, org, user := string(scope.TenantID), string(scope.OrganizationID), string(scope.UserID)
	previous, oldGeneration, exists, err := readProviderRoleGrantSet(ctx, w, scope)
	if err != nil {
		return err
	}
	if exists {
		if update.generation < oldGeneration || update.grants.CheckReplacement(previous) != nil {
			return identity.ConflictError{}
		}
	} else {
		// All writers serialize on the same exact membership row. Check the read
		// profile's bound before inserting another retained provider identity.
		rows, err := w.Query(ctx, `SELECT count(*) FROM (SELECT 1 FROM organization.provider_role_grants
WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 LIMIT 128) g`, tenant, org, user)
		var retained int64
		if err := one(rows, err, &retained); err != nil {
			return err
		}
		if retained >= 128 {
			return identity.ConflictError{}
		}
	}
	roles, err := json.Marshal(input.RoleIDs)
	if err != nil {
		return identity.UnavailableError{}
	}
	if len(input.RoleIDs) != 0 {
		rows, err := w.Query(ctx, `SELECT count(*) FROM organization.custom_roles WHERE tenant_id=$1 AND organization_id=$2 AND state='active'
AND role_id IN (SELECT value FROM jsonb_array_elements_text($3::jsonb))`, tenant, org, string(roles))
		var active int64
		if err := one(rows, err, &active); err != nil {
			return err
		}
		if active != int64(len(input.RoleIDs)) {
			return identity.ForbiddenError{}
		}
	}
	expectedVersion, err := providerRoleOrganizationVersion(update.member.Version, input, update.generation, previous, oldGeneration, exists)
	if err != nil {
		return identity.ConflictError{}
	}
	if expectedVersion != update.expectedOrganizationVersion {
		return identity.ConflictError{}
	}
	changesAuthority := expectedVersion != update.member.Version
	if err := r.reconcileProviderRoleAuthorization(ctx, w, update.member, changesAuthority); err != nil {
		return err
	}
	if changesAuthority {
		n, err := w.Exec(ctx, `UPDATE organization.organizations SET version=$5::numeric
WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND credential_version=$4::numeric AND state='active'`,
			tenant, org, update.member.Version, update.member.CredentialVersion, expectedVersion)
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	return saveProviderRoleGrantUpdate(ctx, w, update, input, string(roles))
}

func providerRoleOrganizationVersion(version uint64, input organization.ProviderRoleGrantInput, generation uint64, previous organization.ProviderRoleGrantSet, oldGeneration uint64, exists bool) (uint64, error) {
	old, _ := previous.Value()
	oldCurrent := exists && old.MemberVersion == input.MemberVersion && old.MappingVersion == input.MappingVersion && oldGeneration == generation
	changesAuthority := len(input.RoleIDs) != 0
	if oldCurrent {
		changesAuthority = !slices.Equal(old.RoleIDs, input.RoleIDs)
	}
	if !changesAuthority {
		return version, nil
	}
	if version == math.MaxUint64 {
		return 0, organization.ErrConflict
	}
	return version + 1, nil
}

func (r *Repository) reconcileProviderRoleAuthorization(ctx context.Context, w kernel.Work, observation organization.CredentialAuthorityObservation, changed bool) error {
	member := observation.Actor
	scope, err := OrganizationAuthorityScope(member.TenantID, member.OrganizationID, member.UserID)
	if err != nil {
		return err
	}
	if !changed {
		return authorityError(authority.RequireAuthority(ctx, w, scope, member.AuthorizationVersion, r.maximum))
	}
	next, err := authority.AdvanceAuthority(ctx, w, scope, member.AuthorizationVersion, r.maximum)
	if err != nil {
		return authorityError(err)
	}
	n, err := w.Exec(ctx, `UPDATE organization.memberships SET authorization_version=$4::numeric
WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND authorization_version=$5::numeric`, string(member.TenantID), string(member.OrganizationID), string(member.UserID), next.Version, member.AuthorizationVersion)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func saveProviderRoleGrantUpdate(ctx context.Context, w kernel.Work, update *providerRoleGrantUpdateState, input organization.ProviderRoleGrantInput, roles string) error {
	scope := input.Scope
	n, err := w.Exec(ctx, `INSERT INTO organization.provider_role_grants AS old
(tenant_id,organization_id,user_id,provider_id,provider_generation,mapping_version,organization_member_version,flow_started_at,assertion_issued_at,role_ids)
VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7::numeric,$8,$9,ARRAY(SELECT value FROM jsonb_array_elements_text($10::jsonb)))
ON CONFLICT(tenant_id,organization_id,user_id,provider_id) DO UPDATE SET
provider_generation=EXCLUDED.provider_generation,mapping_version=EXCLUDED.mapping_version,organization_member_version=EXCLUDED.organization_member_version,
flow_started_at=EXCLUDED.flow_started_at,assertion_issued_at=EXCLUDED.assertion_issued_at,role_ids=EXCLUDED.role_ids
WHERE old.flow_started_at<EXCLUDED.flow_started_at AND old.assertion_issued_at<=EXCLUDED.assertion_issued_at
AND old.provider_generation<=EXCLUDED.provider_generation AND old.mapping_version<=EXCLUDED.mapping_version
AND old.organization_member_version<=EXCLUDED.organization_member_version`, string(scope.TenantID), string(scope.OrganizationID), string(scope.UserID), string(scope.ProviderID),
		update.generation, input.MappingVersion, input.MemberVersion, input.OriginalFlowStartedAt, input.AssertedAt, roles)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if input.OriginalFlowStartedAt.After(now) || update.member.Validate(providerRoleMemberQuery(input.Scope), now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}
