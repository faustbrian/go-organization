package organization

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

const (
	ReserveDomain  Operation = "identity.organization.domain.reserve"
	WithdrawDomain Operation = "identity.organization.domain.withdraw"
	GetDomainClaim Operation = "identity.organization.domain.get"
)

// DomainConfig explicitly selects reservation custody, never ownership proof or
// SSO routing. Zero disables it. Version binds the immutable deployed policy;
// MaximumClaims bounds all retained claims (including withdrawn tombstones) per
// organization to 1..10,000. There is no expiry or automatic takeover.
type DomainConfig struct{ Version, MaximumClaims uint64 }

func (c DomainConfig) Validate() error {
	if c == (DomainConfig{}) {
		return nil
	}
	if c.Version == 0 || c.MaximumClaims < 1 || c.MaximumClaims > 10000 {
		return ErrInvalidInput
	}
	return nil
}

// DomainClaimState is the closed reservation-only lifecycle. Neither state is
// domain ownership evidence. Future challenge/proof profiles remain unselected.
type DomainClaimState string

const (
	DomainRequested DomainClaimState = "requested"
	DomainWithdrawn DomainClaimState = "withdrawn"
)

// DomainClaim is a primary custody snapshot bound to an immutable claim identity
// and exact tenant/organization. Withdrawal advances Version and retains the
// original Domain and ID forever; a later reservation requires a new ID.
type DomainClaim struct {
	ID, OrganizationID ID
	TenantID           identity.TenantID
	Domain             string
	Version            uint64
	State              DomainClaimState
}

// CanonicalDomain implements this profile's deterministic ASCII-only name
// policy: 2 or more LDH labels, 1..63 bytes each, at most 253 canonical bytes,
// and a final label containing at least one ASCII letter. ASCII case folds and
// one terminal root dot is removed. Whitespace, wildcard, IP literals, Unicode and implicit IDNA
// conversion are rejected, not trimmed or interpreted. An ASCII A-label is
// treated as supplied ASCII; this function makes no IDNA conformance claim.
func CanonicalDomain(input string) (string, error) {
	if len(input) < 3 || len(input) > 254 {
		return "", ErrInvalidInput
	}
	input = strings.TrimSuffix(input, ".")
	if len(input) > 253 {
		return "", ErrInvalidInput
	}
	start, labels, finalAlpha := 0, 0, false
	for i := 0; i <= len(input); i++ {
		if i == len(input) || input[i] == '.' {
			if i-start < 1 || i-start > 63 || input[start] == '-' || input[i-1] == '-' {
				return "", ErrInvalidInput
			}
			labels++
			if i == len(input) {
				break
			}
			start, finalAlpha = i+1, false
			continue
		}
		b := input[i]
		if b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' {
			finalAlpha = true
		} else if !(b >= '0' && b <= '9' || b == '-') {
			return "", ErrInvalidInput
		}
	}
	if labels < 2 || !finalAlpha {
		return "", ErrInvalidInput
	}
	return strings.ToLower(input), nil
}

// DomainClaimRequest freezes an exact tenant/org, immutable ClaimID, canonical
// Domain and expected organization epoch. Reserve requires ClaimVersion zero;
// withdraw requires the exact current requested version. Preserve CommandID and
// the original prepared command for replay; never retry Unknown with a new ID.
type DomainClaimRequest struct {
	Authentication                    Authentication
	CommandID                         identity.CommandID
	OrganizationID, ClaimID           ID
	OrganizationVersion, ClaimVersion uint64
	Domain, CorrelationID             string
}

// DomainClaimReadRequest selects only an own-organization immutable claim ID,
// including its withdrawn tombstone. It cannot search for a competing owner.
type DomainClaimReadRequest struct {
	Authentication          Authentication
	OrganizationID, ClaimID ID
	CorrelationID           string
}

func domainMutation(op Operation) bool { return op == ReserveDomain || op == WithdrawDomain }

func (s *Service) PrepareReserveDomain(ctx context.Context, r DomainClaimRequest) (Command, error) {
	return s.prepareDomain(ctx, r, ReserveDomain)
}
func (s *Service) PrepareWithdrawDomain(ctx context.Context, r DomainClaimRequest) (Command, error) {
	return s.prepareDomain(ctx, r, WithdrawDomain)
}

func (s *Service) prepareDomain(ctx context.Context, r DomainClaimRequest, op Operation) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || s.config.Domains.MaximumClaims == 0 || !safeID(string(r.OrganizationID)) || !safeID(string(r.ClaimID)) || !safeID(r.CorrelationID) || r.OrganizationVersion == 0 || r.OrganizationVersion == ^uint64(0) || op == ReserveDomain && r.ClaimVersion != 0 || op == WithdrawDomain && (r.ClaimVersion == 0 || r.ClaimVersion == ^uint64(0)) {
		return out, ErrInvalidInput
	}
	if _, e := identity.ParseCommandID(string(r.CommandID)); e != nil {
		return out, ErrInvalidInput
	}
	domain, e := CanonicalDomain(r.Domain)
	if e != nil {
		return out, e
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil || s.config.ValidateCanonicalID(bounded, r.ClaimID) != nil {
		return out, ErrInvalidInput
	}
	observed, actor, e := s.authenticate(bounded, r.Authentication)
	if e != nil {
		return out, e
	}
	v, e := s.repository.Read(bounded, Query{Operation: op, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, DomainClaimID: r.ClaimID})
	if e != nil {
		return out, publicError(bounded, e)
	}
	if !validView(v, r.Authentication.TenantID, r.OrganizationID, actor) || v.Actor.Role != RoleOwner && v.Actor.Role != RoleAdministrator {
		return out, ErrForbidden
	}
	if e = s.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, op, r.CorrelationID); e != nil {
		return out, e
	}
	if v.Organization.Version != r.OrganizationVersion {
		return out, ErrConflict
	}
	claim := v.DomainClaim
	if op == ReserveDomain {
		if claim != (DomainClaim{}) {
			return out, ErrConflict
		}
		claim = DomainClaim{ID: r.ClaimID, OrganizationID: r.OrganizationID, TenantID: r.Authentication.TenantID, Domain: domain, State: DomainRequested}
	} else {
		if !validDomainClaim(claim, r.Authentication.TenantID, r.OrganizationID, r.ClaimID) {
			return out, ErrForbidden
		}
		if claim.Version != r.ClaimVersion || claim.Domain != domain || claim.State != DomainRequested {
			return out, ErrConflict
		}
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	if e = bounded.Err(); e != nil {
		return out, e
	}
	out = s.command(r.CommandID, op, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, Member{}, identity.User{ID: actor, TenantID: r.Authentication.TenantID}, "")
	out.state.input.Binding.SchemaID = op.Descriptor().SchemaID
	out.state.input.DomainClaim, out.state.input.Domains = claim, s.config.Domains
	return out, nil
}

func validDomainClaim(c DomainClaim, tenant identity.TenantID, org, id ID) bool {
	domain, err := CanonicalDomain(c.Domain)
	return err == nil && domain == c.Domain && c.ID == id && c.OrganizationID == org && c.TenantID == tenant && (c.State == DomainRequested && c.Version == 1 || c.State == DomainWithdrawn && c.Version == 2)
}

// GetDomainClaim discloses current custody only to a current owner/admin after
// current policy and a second primary membership/session read. It is not proof.
func (s *Service) GetDomainClaim(ctx context.Context, r DomainClaimReadRequest) (out View, err error) {
	defer func() {
		if recover() != nil {
			out, err = View{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || s.config.Domains.MaximumClaims == 0 || !safeID(string(r.OrganizationID)) || !safeID(string(r.ClaimID)) || !safeID(r.CorrelationID) {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil || s.config.ValidateCanonicalID(bounded, r.ClaimID) != nil {
		return out, ErrInvalidInput
	}
	observed, actor, e := s.authenticate(bounded, r.Authentication)
	if e != nil {
		return out, e
	}
	q := Query{Operation: GetDomainClaim, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, DomainClaimID: r.ClaimID}
	v, e := s.repository.Read(bounded, q)
	if e != nil {
		return out, publicError(bounded, e)
	}
	if !validView(v, q.TenantID, q.OrganizationID, actor) || v.Actor.Role != RoleOwner && v.Actor.Role != RoleAdministrator {
		return out, ErrForbidden
	}
	if e = s.authorize(bounded, actor, q.TenantID, q.OrganizationID, v.Organization.Version, GetDomainClaim, r.CorrelationID); e != nil {
		return out, e
	}
	if _, current, e := s.authenticate(bounded, r.Authentication); e != nil || current != actor {
		if e != nil {
			return out, e
		}
		return out, ErrForbidden
	}
	fresh, e := s.repository.Read(bounded, q)
	if e != nil {
		return out, publicError(bounded, e)
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil || !validView(fresh, q.TenantID, q.OrganizationID, actor) || fresh.Organization != v.Organization || fresh.Actor != v.Actor || !validDomainClaim(fresh.DomainClaim, q.TenantID, q.OrganizationID, q.DomainClaimID) {
		return out, ErrForbidden
	}
	if e = bounded.Err(); e != nil {
		return out, e
	}
	// Repository may implement other views; this operation releases only custody.
	return View{Organization: fresh.Organization, Actor: fresh.Actor, DomainClaim: fresh.DomainClaim}, nil
}
