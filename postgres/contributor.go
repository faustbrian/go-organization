package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

// ContributorConfig fixes the one password/bearer profile and immutable limits.
// LookupKeys maps the original retained version to opaque session-owned keys.
// Keys, pool and owner lifetimes remain caller-owned; no key may be retired while
// a supported original session or pending command requires it. PolicyNamespace
// in Profile belongs to session authentication, not organization membership.
type ContributorConfig struct {
	Session                                          sessionpg.Config
	Profile                                          sessionpg.IdentifierAdmissionConfig
	LookupKeys                                       map[uint32]session.DigestKey
	PolicyID                                         string
	PolicyVersion                                    uint64
	MaximumMembers, MaximumPerUser, MaximumPerTenant uint64
	Teams                                            organization.TeamConfig
	Domains                                          organization.DomainConfig
	// OwnerTransferPrimary explicitly enables the operation-bound password
	// profile. Omission preserves the original operation set and command bytes.
	OwnerTransferPrimary *passwordpg.ActionPrimarySource
}

// Contributor is an immutable open registered participant, not a coordinator or
// permission engine. It only operates on the original serial invocation's Work.
// Separate invocations may execute concurrently; it retains no per-call state.
type Contributor struct {
	repository *Repository
	config     ContributorConfig
}

var _ kernel.FeatureCommitContributor = (*Contributor)(nil)

func NewContributor(repository *Repository, c ContributorConfig) (*Contributor, error) {
	if repository == nil || c.Session.MaximumDuration <= 0 || c.Session.MaximumDuration > 5*time.Second || c.Profile.Validate() != nil || c.Profile.AuthenticationMethod != "password" || c.Profile.CredentialKind != identity.CredentialPassword || c.Profile.CredentialOwner != "identity/password" || !scope(c.PolicyID) || c.PolicyVersion == 0 || c.MaximumMembers < 1 || c.MaximumMembers > 100000 || c.MaximumPerUser < 1 || c.MaximumPerUser > 1000 || c.MaximumPerTenant < 1 || c.MaximumPerTenant > 1000000 || len(c.LookupKeys) < 1 || len(c.LookupKeys) > 4 || c.Teams.Validate() != nil || c.Domains.Validate() != nil {
		return nil, organization.ErrInvalidInput
	}
	keys := make(map[uint32]session.DigestKey, len(c.LookupKeys))
	probe, _ := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	for version, key := range c.LookupKeys {
		d, e := probe.Digest(key, "validation")
		if e != nil || d.KeyVersion != version {
			return nil, organization.ErrInvalidInput
		}
		keys[version] = key
	}
	c.LookupKeys = keys
	return &Contributor{repository: repository, config: c}, nil
}

func (*Contributor) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.membership", Version: 1}
}
func (p *Contributor) FeatureOperations() []identity.FeatureOperation {
	ops := []identity.FeatureOperation{organization.Create.Descriptor(), organization.Update.Descriptor(), organization.AddMember.Descriptor(), organization.UpdateMember.Descriptor(), organization.RemoveMember.Descriptor(), organization.LeaveMember.Descriptor()}
	if p != nil && p.config.OwnerTransferPrimary != nil {
		ops = append(ops, organization.OwnerTransfer.Descriptor())
	}
	if p != nil && p.config.Domains.MaximumClaims > 0 {
		ops = append(ops, organization.ReserveDomain.Descriptor(), organization.WithdrawDomain.Descriptor())
	}
	if p != nil && p.config.Teams.MaximumTeams > 0 {
		ops = append(ops, organization.CreateTeam.Descriptor(), organization.AddTeamMember.Descriptor(), organization.RemoveTeamMember.Descriptor())
		if p.config.Teams.LifecycleVersion == 1 {
			ops = append(ops, organization.UpdateTeam.Descriptor(), organization.DeleteTeam.Descriptor())
		}
	}
	return ops
}
func (ContributorConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.ContributorConfig(redacted)"))
}
func (ContributorConfig) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (ContributorConfig) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

type nativeCommand struct {
	spec                                    identity.FeatureCommandSpec
	operation                               organization.Operation
	org                                     organization.Organization
	actor, target                           organization.Member
	user                                    identity.User
	role                                    organization.Role
	original                                session.Session
	until                                   time.Time
	team                                    organization.Team
	teamMember                              organization.TeamMember
	domainClaim                             organization.DomainClaim
	actorFactorVersion, targetFactorVersion uint64
}

func text(name, value string) identity.FeatureField {
	return identity.FeatureField{Name: "organization." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
}
func number(name string, value uint64) identity.FeatureField {
	return identity.FeatureField{Name: "organization." + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
}

// MapCommand freezes every domain option and the native session owner's complete
// original fields. Bearer custody remains in identity.NewFeatureSessionCommand,
// never in scalar metadata, persistence results or audit/outbox payloads.
// OwnerTransfer requires Service.PrepareOwnerTransfer's authenticated password
// admission and is rejected here rather than mapped without its proof owner.
func (p *Contributor) MapCommand(c organization.Command) (identity.Command, error) {
	x, e := c.Input()
	if e != nil || p == nil || p.repository == nil || x.MaximumMembers != p.config.MaximumMembers || x.MaximumPerUser != p.config.MaximumPerUser || x.MaximumPerTenant != p.config.MaximumPerTenant || x.Binding.PolicyID != p.config.PolicyID || x.Binding.PolicyVersion != p.config.PolicyVersion {
		return identity.Command{}, organization.ErrInvalidInput
	}
	if x.Operation == organization.OwnerTransfer {
		// Its source-owned proof framing requires authenticated primary
		// admission; the public Service performs that bounded preparation.
		return identity.Command{}, organization.ErrInvalidInput
	}
	f, e := sessionpg.OriginalSessionFields(x.Session.Session)
	if e != nil {
		return identity.Command{}, organization.ErrForbidden
	}
	f = append(f, membershipFields(x)...)
	if isDomainMutation(x.Operation) {
		if p.config.Domains.MaximumClaims == 0 || x.Domains != p.config.Domains {
			return identity.Command{}, organization.ErrInvalidInput
		}
		f = append(f, text("claim-id", string(x.DomainClaim.ID)), text("domain", x.DomainClaim.Domain), text("claim-state", string(x.DomainClaim.State)), number("claim-version", x.DomainClaim.Version), number("domain-policy-version", x.Domains.Version), number("maximum-domain-claims", x.Domains.MaximumClaims))
	}
	if isTeamMutation(x.Operation) {
		if p.config.Teams.MaximumTeams == 0 || x.Teams != p.config.Teams {
			return identity.Command{}, organization.ErrInvalidInput
		}
		f = append(f, text("team-id", string(x.Team.ID)), text("team-name", x.Team.Name), number("team-version", x.Team.Version), number("team-member-version", x.TeamMember.Version), number("team-member-organization-version", x.TeamMember.OrganizationMemberVersion), number("team-policy-version", x.Teams.Version), number("maximum-teams", x.Teams.MaximumTeams), number("maximum-team-members", x.Teams.MaximumMembers))
		if isTeamLifecycle(x.Operation) {
			if x.Teams.LifecycleVersion != 1 {
				return identity.Command{}, organization.ErrInvalidInput
			}
			f = append(f, number("team-lifecycle-version", x.Teams.LifecycleVersion))
		}
	}
	return identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: x.Binding, Operation: x.Operation.Descriptor(), Fields: f}, x.Bearer)
}

func membershipFields(x organization.CommandInput) []identity.FeatureField {
	return []identity.FeatureField{number("version", x.Organization.Version), text("slug", x.Organization.Slug), text("name", x.Organization.Name), number("actor-version", x.Actor.Version), text("actor-role", string(x.Actor.Role)), number("actor-authorization", x.Actor.AuthorizationVersion), number("member-version", x.Target.Version), text("member-role", string(x.Target.Role)), number("member-authorization", x.Target.AuthorizationVersion), number("target-version", x.TargetUser.Version), text("target-status", string(x.TargetUser.Status)), text("role", string(x.Role)), number("maximum-members", x.MaximumMembers), number("maximum-per-user", x.MaximumPerUser), number("maximum-per-tenant", x.MaximumPerTenant), text("session-until", x.Session.ValidUntil().UTC().Format(time.RFC3339Nano))}
}

func (p *Contributor) decode(command identity.Command) (nativeCommand, error) {
	bad := func() (nativeCommand, error) { return nativeCommand{}, organization.ErrInvalidInput }
	if p == nil || p.repository == nil {
		return bad()
	}
	s, ok := command.Feature()
	if !ok {
		return bad()
	}
	op := organization.Operation(s.Binding.OperationID)
	if s.Operation != op.Descriptor() || s.Operation.Validate() != nil || s.Binding.ActorKind != authorization.SubjectUser || s.Binding.PolicyID != p.config.PolicyID || s.Binding.PolicyVersion != p.config.PolicyVersion {
		return bad()
	}
	values := map[string]identity.FeatureValue{}
	original := []identity.FeatureField{}
	actorFactorVersion, targetFactorVersion := uint64(0), uint64(0)
	for _, f := range s.Fields {
		if strings.HasPrefix(f.Name, "source-session.") {
			original = append(original, f)
		} else if strings.HasPrefix(f.Name, "organization.") {
			if _, has := values[f.Name]; has {
				return bad()
			}
			values[f.Name] = f.Value
		} else if op == organization.OwnerTransfer && (f.Name == "action-primary.actor-factor-version" || f.Name == "action-primary.target-factor-version") {
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 == 0 {
				return bad()
			}
			destination := &actorFactorVersion
			if f.Name == "action-primary.target-factor-version" {
				destination = &targetFactorVersion
			}
			if *destination != 0 {
				return bad()
			}
			*destination = f.Value.Uint64
		} else if op == organization.OwnerTransfer && strings.HasPrefix(f.Name, "password.action-primary.") {
			// Only the password owner decodes/authenticates this original frame.
			// Apply and final commit must restore it before admitting effects.
		} else if !strings.HasPrefix(f.Name, "counter.") {
			return bad()
		}
	}
	want := 16
	if isDomainMutation(op) {
		want += 6
	}
	if isTeamMutation(op) {
		want += 8
		if isTeamLifecycle(op) {
			want++
		}
	}
	if len(values) != want {
		return bad()
	}
	if op == organization.OwnerTransfer && (actorFactorVersion == 0 || targetFactorVersion == 0) {
		return bad()
	}
	textNames := []string{"slug", "name", "actor-role", "member-role", "target-status", "role", "session-until"}
	numberNames := []string{"version", "actor-version", "actor-authorization", "member-version", "member-authorization", "target-version", "maximum-members", "maximum-per-user", "maximum-per-tenant"}
	if isDomainMutation(op) {
		textNames = append(textNames, "claim-id", "domain", "claim-state")
		numberNames = append(numberNames, "claim-version", "domain-policy-version", "maximum-domain-claims")
	}
	if isTeamMutation(op) {
		textNames = append(textNames, "team-id", "team-name")
		numberNames = append(numberNames, "team-version", "team-member-version", "team-member-organization-version", "team-policy-version", "maximum-teams", "maximum-team-members")
		if isTeamLifecycle(op) {
			numberNames = append(numberNames, "team-lifecycle-version")
		}
	}
	for _, key := range textNames {
		if values["organization."+key].Kind != identity.FeatureText {
			return bad()
		}
	}
	for _, key := range numberNames {
		if values["organization."+key].Kind != identity.FeatureUint64 {
			return bad()
		}
	}
	t := func(k string) string { return values["organization."+k].Text }
	n := func(k string) uint64 { return values["organization."+k].Uint64 }
	if n("maximum-members") != p.config.MaximumMembers || n("maximum-per-user") != p.config.MaximumPerUser || n("maximum-per-tenant") != p.config.MaximumPerTenant {
		return bad()
	}
	record, e := sessionpg.OriginalSessionFromFields(s.Binding.TenantID, identity.UserID(s.Binding.ActorID), original)
	if e != nil {
		return bad()
	}
	until, e := time.Parse(time.RFC3339Nano, t("session-until"))
	if e != nil || until.IsZero() || until.UTC().Format(time.RFC3339Nano) != t("session-until") {
		return bad()
	}
	c := nativeCommand{spec: s, operation: op, org: organization.Organization{ID: organization.ID(s.Binding.RecordID), TenantID: s.Binding.TenantID, Slug: t("slug"), Name: t("name"), Version: n("version"), Active: true}, actor: organization.Member{OrganizationID: organization.ID(s.Binding.RecordID), TenantID: s.Binding.TenantID, UserID: identity.UserID(s.Binding.ActorID), Role: organization.Role(t("actor-role")), Version: n("actor-version"), AuthorizationVersion: n("actor-authorization"), Active: true}, target: organization.Member{OrganizationID: organization.ID(s.Binding.RecordID), TenantID: s.Binding.TenantID, UserID: s.Binding.UserID, Role: organization.Role(t("member-role")), Version: n("member-version"), AuthorizationVersion: n("member-authorization")}, user: identity.User{ID: s.Binding.UserID, TenantID: s.Binding.TenantID, Version: n("target-version"), Status: identity.Status(t("target-status"))}, role: organization.Role(t("role")), original: record, until: until, actorFactorVersion: actorFactorVersion, targetFactorVersion: targetFactorVersion}
	if isDomainMutation(op) {
		domain, err := organization.CanonicalDomain(t("domain"))
		if p.config.Domains.MaximumClaims == 0 || n("domain-policy-version") != p.config.Domains.Version || n("maximum-domain-claims") != p.config.Domains.MaximumClaims || err != nil || domain != t("domain") || !scope(t("claim-id")) || c.org.Version == 0 || c.org.Version == ^uint64(0) || c.actor.Version == 0 || c.actor.AuthorizationVersion == 0 || c.actor.Role != organization.RoleOwner && c.actor.Role != organization.RoleAdministrator || c.target.Version != 0 || c.target.AuthorizationVersion != 0 || c.target.Role != "" || c.user.Version != 0 || c.user.Status != "" || c.role != "" || string(s.Binding.UserID) != string(s.Binding.ActorID) || t("claim-state") != string(organization.DomainRequested) || op == organization.ReserveDomain && n("claim-version") != 0 || op == organization.WithdrawDomain && n("claim-version") != 1 {
			return bad()
		}
		c.domainClaim = organization.DomainClaim{ID: organization.ID(t("claim-id")), OrganizationID: c.org.ID, TenantID: s.Binding.TenantID, Domain: domain, State: organization.DomainRequested, Version: n("claim-version")}
	} else if isTeamMutation(op) {
		if p.config.Teams.MaximumTeams == 0 || n("team-policy-version") != p.config.Teams.Version || n("maximum-teams") != p.config.Teams.MaximumTeams || n("maximum-team-members") != p.config.Teams.MaximumMembers || !scope(t("team-id")) || !boundedTeamName(t("team-name")) || c.org.Version == 0 || c.org.Version == ^uint64(0) || c.actor.Version == 0 || c.actor.AuthorizationVersion == 0 || c.actor.Role != organization.RoleOwner && c.actor.Role != organization.RoleAdministrator || c.role != "" {
			return bad()
		}
		c.team = organization.Team{ID: organization.ID(t("team-id")), OrganizationID: c.org.ID, TenantID: s.Binding.TenantID, Name: t("team-name"), Version: n("team-version")}
		c.teamMember = organization.TeamMember{TeamID: c.team.ID, OrganizationID: c.org.ID, TenantID: s.Binding.TenantID, UserID: s.Binding.UserID, Version: n("team-member-version"), OrganizationMemberVersion: n("team-member-organization-version")}
		if isTeamLifecycle(op) {
			if p.config.Teams.LifecycleVersion != 1 || n("team-lifecycle-version") != 1 || c.team.Version == 0 || c.team.Version == ^uint64(0) || c.teamMember.Version != 0 || c.teamMember.OrganizationMemberVersion != 0 || c.target.Version != 0 || c.target.AuthorizationVersion != 0 || c.target.Role != "" || c.user.Version != 0 || c.user.Status != "" || string(s.Binding.UserID) != string(s.Binding.ActorID) {
				return bad()
			}
		} else if op == organization.CreateTeam {
			if c.team.Version != 0 || c.teamMember.Version != 0 || c.teamMember.OrganizationMemberVersion != 0 || c.target.Version != 0 || c.target.AuthorizationVersion != 0 || c.target.Role != "" || c.user.Version != 0 || c.user.Status != "" || string(s.Binding.UserID) != string(s.Binding.ActorID) {
				return bad()
			}
		} else if c.team.Version == 0 || c.team.Version == ^uint64(0) || c.teamMember.Version == ^uint64(0) || c.target.Version == 0 || c.target.AuthorizationVersion == 0 || !c.target.Role.Valid() || c.user.Validate(s.Binding.TenantID) != nil || c.user.Status != identity.StatusActive || op == organization.RemoveTeamMember && c.teamMember.Version == 0 {
			return bad()
		}
	} else if op == organization.Create {
		if c.org.Version != 0 || c.actor.Version != 0 || c.target.Version != 0 || c.role != organization.RoleOwner || string(s.Binding.ActorID) != string(s.Binding.UserID) || c.user.Version != 0 {
			return bad()
		}
	} else if op == organization.Update {
		if c.org.Version == 0 || c.org.Version == ^uint64(0) || c.actor.Version == 0 || c.actor.AuthorizationVersion == 0 || c.actor.Role != organization.RoleOwner && c.actor.Role != organization.RoleAdministrator || c.target.Version != 0 || c.target.AuthorizationVersion != 0 || c.target.Role != "" || c.role != "" || c.user.Version != 0 || c.user.Status != "" || string(s.Binding.ActorID) != string(s.Binding.UserID) || !validMetadata(c.org.Name, c.org.Slug) {
			return bad()
		}
	} else {
		if c.org.Version == 0 || c.org.Version == ^uint64(0) || c.actor.Version == 0 || c.actor.AuthorizationVersion == 0 || op != organization.LeaveMember && c.actor.Role != organization.RoleOwner && c.actor.Role != organization.RoleAdministrator || c.user.Validate(s.Binding.TenantID) != nil {
			return bad()
		}
		// The public contributor also accepts directly constructed native
		// commands: self-leave cannot become an arbitrary-target removal grant.
		if op == organization.LeaveMember && (s.Binding.UserID != identity.UserID(s.Binding.ActorID) || !c.actor.Role.Valid() || c.target.Version != c.actor.Version || c.target.AuthorizationVersion != c.actor.AuthorizationVersion || c.target.Role != c.actor.Role || c.role != "" || c.user.Status != identity.StatusActive) {
			return bad()
		}
		if op == organization.AddMember && (!c.role.Valid() || c.user.Status != identity.StatusActive || c.role == organization.RoleOwner && c.actor.Role != organization.RoleOwner) {
			return bad()
		}
		if op == organization.RemoveMember && (c.target.Version == 0 || !c.target.Role.Valid() || c.target.AuthorizationVersion == 0 || c.role != "" || c.target.Role == organization.RoleOwner && c.actor.Role != organization.RoleOwner) {
			return bad()
		}
		if op == organization.UpdateMember && (c.target.Version == 0 || c.target.Version == ^uint64(0) || !c.target.Role.Valid() || c.target.AuthorizationVersion == 0 || !c.role.Valid() || c.role == c.target.Role || c.user.Status != identity.StatusActive || (c.target.Role == organization.RoleOwner || c.role == organization.RoleOwner) && c.actor.Role != organization.RoleOwner) {
			return bad()
		}
		if op == organization.OwnerTransfer && (p.config.OwnerTransferPrimary == nil || c.actor.Role != organization.RoleOwner || c.actor.Version == ^uint64(0) || c.target.Version == 0 || c.target.Version == ^uint64(0) || !c.target.Role.Valid() || c.target.Role == organization.RoleOwner || c.target.AuthorizationVersion == 0 || c.role != organization.RoleMember || c.user.Status != identity.StatusActive || string(s.Binding.ActorID) == string(s.Binding.UserID)) {
			return bad()
		}
	}
	return c, nil
}

func (p *Contributor) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	c, e := p.decode(command)
	if e != nil {
		return e
	}
	event, action := events(c.operation)
	if plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != c.spec.Operation || plan.SubjectType != "organization" || plan.Lifecycle == nil || plan.Lifecycle.EventType != event || plan.Lifecycle.BeforeVersion != c.org.Version || plan.Lifecycle.AfterVersion != c.org.Version+1 || len(plan.Audits) != 1 || plan.Audits[0].EventType != action || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.Delivery != nil || plan.CommandCounters == nil {
		return organization.ErrInvalidInput
	}
	return nil
}

func events(op organization.Operation) (string, string) {
	switch op {
	case organization.ReserveDomain:
		return "organization.domain_reserved.v1", string(organization.ReserveDomain)
	case organization.WithdrawDomain:
		return "organization.domain_withdrawn.v1", string(organization.WithdrawDomain)
	case organization.Create:
		return "organization.created.v1", "identity.organization.create"
	case organization.Update:
		return "organization.updated.v1", "identity.organization.update"
	case organization.AddMember:
		return "membership.created.v1", "identity.organization.add_member"
	case organization.UpdateMember:
		return "membership.role_changed.v1", "identity.organization.change_member_role"
	case organization.RemoveMember, organization.LeaveMember:
		// SECURITY_EVENTS declares the protected membership-removal effect.
		// Callable leave keeps its own self-only command and policy identity.
		return "membership.removed.v1", "identity.organization.remove_member"
	case organization.OwnerTransfer:
		return "organization.ownership_transferred.v1", "identity.organization.transfer_ownership"
	case organization.CreateTeam:
		return "team.created.v1", "identity.organization.create_team"
	case organization.AddTeamMember:
		return "team.membership_changed.v1", "identity.organization.add_team_member"
	case organization.RemoveTeamMember:
		return "team.membership_changed.v1", "identity.organization.remove_team_member"
	case organization.UpdateTeam:
		return "team.updated.v1", "identity.organization.update_team"
	case organization.DeleteTeam:
		return "team.deleted.v1", "identity.organization.delete_team"
	}
	return "", ""
}

// The native public contributor must enforce the same bounded, non-normalizing
// metadata contract even when a caller supplies a feature command directly.
func validMetadata(name, slug string) bool {
	if len(name) == 0 || len(name) > 256 || !utf8.ValidString(name) || strings.TrimSpace(name) != name || len(slug) == 0 || len(slug) > 63 || slug[0] == '-' || slug[len(slug)-1] == '-' {
		return false
	}
	for _, r := range name {
		if r < ' ' || r == 127 {
			return false
		}
	}
	for _, b := range []byte(slug) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return true
}

func (p *Contributor) admit(ctx context.Context, w kernel.Work, c nativeCommand, command identity.Command, final bool) error {
	if ctx == nil || p == nil {
		return organization.ErrInvalidInput
	}
	if _, _, _, e := w.FeatureScope(p); e != nil {
		return e
	}
	if !final {
		if e := w.RequireFeatureCommand(ctx, p, command); e != nil {
			return e
		}
	}
	s, e := c.original.Bindings()
	if e != nil {
		return identity.ForbiddenError{}
	}
	borrowed, ok := command.SessionToken()
	if !ok {
		return identity.ForbiddenError{}
	}
	token, e := session.ParseToken(borrowed.Token())
	if e != nil {
		return identity.ForbiddenError{}
	}
	key, ok := p.config.LookupKeys[s.Lookup.KeyVersion]
	if !ok {
		return identity.ForbiddenError{}
	}
	digest, e := token.Digest(key, string(s.TenantID))
	if e != nil || digest.KeyVersion != s.Lookup.KeyVersion || subtle.ConstantTimeCompare(digest.Sum[:], s.Lookup.Sum[:]) != 1 {
		return identity.ForbiddenError{}
	}
	b := c.spec.Binding
	b.UserID = identity.UserID(b.ActorID)
	d, credential, policy, e := sessionpg.OriginalSessionAdmission(p.config.Profile, c.original, b)
	if e != nil {
		return identity.ForbiddenError{}
	}
	if e = w.RequireActiveDirectoryAuthority(ctx, p, d); e != nil {
		return e
	}
	// Kernel RequireEmailRemovalSubjects acquires both user rows FOR UPDATE
	// ORDER BY user_id. Our SHARE locks commute with each other, but retaining
	// the later user while waiting for the first would deadlock with that owner.
	// Order transfer and role-update's two-user admissions; keep legacy paths.
	actorFirst := (c.operation == organization.OwnerTransfer || c.operation == organization.UpdateMember) && string(c.spec.Binding.ActorID) < string(c.spec.Binding.UserID)
	if actorFirst {
		if _, e = w.RequireActiveActorCredential(ctx, p, credential); e != nil {
			return e
		}
	}
	if !final && (c.operation == organization.AddMember || c.operation == organization.UpdateMember || c.operation == organization.AddTeamMember || c.operation == organization.RemoveTeamMember || c.operation == organization.OwnerTransfer) {
		// The existing identity owner fences the exact target; organization
		// never copies identity SQL or invents target security epochs.
		if e = w.RequireActiveTargetUser(ctx, p, c.user); e != nil {
			return e
		}
	}
	if !actorFirst {
		if _, e = w.RequireActiveActorCredential(ctx, p, credential); e != nil {
			return e
		}
	}
	if e = w.RequireActiveActorAuthorization(ctx, p, policy); e != nil {
		return e
	}
	if e = sessionpg.RequireSession(ctx, w, p.config.Session, c.original); e != nil {
		return e
	}
	now, e := w.DatabaseTime(ctx)
	if e != nil {
		return e
	}
	if !now.Before(c.until) || c.until.After(now.Add(20*time.Second)) {
		return identity.ForbiddenError{}
	}
	if c.operation == organization.OwnerTransfer {
		life, err := c.original.Lifetime(now)
		if err != nil || !life.Fresh {
			return identity.ForbiddenError{}
		}
		// The MFA owner locks both real rows in canonical subject order through
		// Work. Repeat at final commit; session validity alone is not this fence.
		return mfapg.RequireActionPrimaryFactors(ctx, w, p, command, c.actorFactorVersion, c.targetFactorVersion)
	}
	return nil
}

// OrganizationAuthorityScope binds target authorization to one organization,
// not the session/global user namespace. The length-framed, domain-separated
// digest keeps a full canonical 128-byte organization ID inside the owner's
// bounded namespace. It supplies no authority or freshness on its own.
func OrganizationAuthorityScope(tenant identity.TenantID, org organization.ID, user identity.UserID) (authority.AuthorityScope, error) {
	if !scope(string(tenant)) || !scope(string(org)) || !scope(string(user)) {
		return authority.AuthorityScope{}, organization.ErrInvalidInput
	}
	h := sha256.Sum256([]byte("golib.organization.authorization.v1\x00" + strconv.Itoa(len(org)) + ":" + string(org)))
	return authority.AuthorityScope{TenantID: authorization.TenantID(tenant), PolicyNamespace: "organization-v1-" + hex.EncodeToString(h[:]), SubjectID: authorization.SubjectID(user)}, nil
}

func (p *Contributor) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	c, e := p.decode(command)
	if e != nil {
		return e
	}
	if c.operation == organization.OwnerTransfer {
		primary, err := p.restoreTransfer(ctx, c, command)
		if err != nil {
			return err
		}
		if err = primary.Check(ctx, w, p, command); err != nil {
			return err
		}
	}
	if isDomainMutation(c.operation) {
		if e = p.checkDomainCommit(ctx, w, c); e != nil {
			return e
		}
	}
	// Domain reads can wait beyond the original observation/session lifetime.
	// Keep their current-state checks before admission's final primary-time
	// fence; neither a successful read nor this hook renews that observation.
	return p.admit(ctx, w, c, command, true)
}
