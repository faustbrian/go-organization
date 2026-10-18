package organization

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
)

const (
	InvitationSend   Operation = "identity.organization.invitation-send"
	InvitationAccept Operation = "identity.organization.invitation.accept"
	InvitationCancel Operation = "identity.organization.invitation.cancel"
	InvitationGet    Operation = "identity.organization.invitation.get"
	InvitationList   Operation = "identity.organization.invitation.list"
)

func invitationDescriptor(o Operation) identity.FeatureOperation {
	schema := ""
	switch o {
	case InvitationSend:
		schema = "organization-invitation-send"
	case InvitationAccept:
		schema = "organization-invitation-accept"
	case InvitationCancel:
		schema = "organization-invitation-cancel"
	default:
		return identity.FeatureOperation{}
	}
	return identity.FeatureOperation{Owner: "organization", OperationID: string(o), SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// InvitationStatus describes the selected durable lifecycle. Zero is invalid.
// Expired is a non-authorizing projection of exclusive expiry, not an exposed
// expire/resend command. Accepted and cancelled records never become pending again.
type InvitationStatus uint8

const (
	InvitationPending InvitationStatus = iota + 1
	InvitationAccepted
	InvitationExpired
	InvitationCancelled
)

// Invitation is safe scalar metadata. It contains neither a transport address
// nor proof/digest/ciphertext. It grants no access and never authenticates its
// recipient. Versions and IDs are exact tenant/organization scoped values.
type Invitation struct {
	ID, OrganizationID         ID
	TenantID                   identity.TenantID
	RecipientUserID            identity.UserID
	RecipientIdentifierID      identity.IdentifierID
	RecipientIdentifierVersion uint64
	CreatedBy                  identity.UserID
	Role                       Role
	Status                     InvitationStatus
	Version                    uint64
	ExpiresAt                  time.Time
}

// InvitationDelivery combines safe invitation metadata with the existing
// delivery owner's state. Accepted is provider acceptance, not Delivered;
// an ambiguous delivery never rolls back an already committed invitation.
// A missing effect is represented by empty EffectID and zero State, never by
// inventing provider failure/success. Command outcomes distinguish no queue
// commitment from an unresolved commit.
type InvitationDelivery struct {
	Invitation Invitation
	EffectID   delivery.IntentID
	State      delivery.DeliveryState
}

// InvitationQuery is a trusted bounded primary projection selected after real
// authentication. Send selects a current verified existing email identifier;
// acceptance does not require the recipient to be a member before mutation.
type InvitationQuery struct {
	Operation                    Operation
	TenantID                     identity.TenantID
	ActorID, RecipientUserID     identity.UserID
	OrganizationID, InvitationID ID
	RecipientIdentifierID        identity.IdentifierID
	Cursor                       ID
	Limit                        uint32
}

// InvitationSnapshot is adapter input, not a public metadata response or a
// permission/proof. Recipient fields are sensitive native owner projections;
// automatic serialization is denied. Durable application must fence their
// original verified identifier and independent security epochs with its owner.
type InvitationSnapshot struct {
	Organization        Organization
	Actor, Target       Member
	RecipientUser       identity.User
	RecipientIdentifier identity.Identifier
	Record              InvitationDelivery
	PendingCount        uint64
}

func (InvitationSnapshot) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationSnapshot(redacted)"))
}
func (InvitationSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (InvitationSnapshot) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// InvitationPage is a current primary keyset page, not a retained snapshot.
// Actor and Organization are current policy inputs, never returned grants.
type InvitationPage struct {
	Organization Organization
	Actor        Member
	Invitations  []InvitationDelivery
	NextCursor   ID
}

// InvitationRepository is the storage-neutral trusted preparation/read port.
// Returned values are independently owned and bounded. It never authenticates
// sessions or consumes a capability. Implementations must support cancellation
// and concurrent independent reads without any positive membership cache.
type InvitationRepository interface {
	ReadInvitation(context.Context, InvitationQuery) (InvitationSnapshot, error)
	ListInvitations(context.Context, InvitationQuery) (InvitationPage, error)
}

// InvitationVerifier consumes the existing capability owner's non-consuming
// cryptographic verification contract. A verified grant is not permission or
// one-use consumption; those remain the native transaction owner's obligation.
type InvitationVerifier interface {
	Verify(context.Context, capability.Proof, capability.Purpose, string) (capability.Grant, error)
}

// InvitationConfig selects owner-send/member-accept and administrator cancellation
// for existing verified
// email recipients. Lifetime follows reference bounds15m..30d; MaximumPending
// follows1..10000. Zero is invalid. The composition selects48h/100 explicitly,
// and must enlarge capability cryptographic lifetime limits to match; the root
// never weakens the capability owner's defaults or creates signing keys.
type InvitationConfig struct {
	Audience       string
	Lifetime       time.Duration
	MaximumPending uint64
}

// InvitationService borrows the existing root service/session/policy and
// explicit repository/verifier. It owns no store, transaction, token engine,
// delivery worker or goroutine. Immutable construction supports concurrency.
type InvitationService struct {
	base       *Service
	repository InvitationRepository
	verifier   InvitationVerifier
	config     InvitationConfig
}

// NewInvitationService validates the explicit finite profile without IO. The
// caller owns borrowed collaborators and their shutdown; none may be mutated
// concurrently with calls. Invalid or zero configuration has no defaults.
func NewInvitationService(base *Service, repository InvitationRepository, verifier InvitationVerifier, c InvitationConfig) (*InvitationService, error) {
	if base == nil || nilValue(repository) || nilValue(verifier) || !safeID(c.Audience) || c.Lifetime < 15*time.Minute || c.Lifetime > 30*24*time.Hour || c.Lifetime%time.Second != 0 || c.MaximumPending < 1 || c.MaximumPending > 10000 {
		return nil, ErrInvalidInput
	}
	c.Audience = strings.Clone(c.Audience)
	return &InvitationService{base: base, repository: repository, verifier: verifier, config: c}, nil
}

// InvitationSendRequest binds a caller-preallocated canonical invitation ID,
// organization/version and exact existing verified recipient identifier. Only
// the static member role is selected; no caller role/team or address is accepted.
type InvitationSendRequest struct {
	Authentication        Authentication
	CommandID             identity.CommandID
	ID, OrganizationID    ID
	OrganizationVersion   uint64
	RecipientUserID       identity.UserID
	RecipientIdentifierID identity.IdentifierID
	CorrelationID         string
}

// InvitationInput is trusted immutable command custody for the native adapter.
// Record is safe metadata; RecipientIdentifier contains sensitive canonical
// email and must enter only authenticated encrypted native preparation custody,
// never command safe_fields, audit, invitation rows or metadata responses.
type InvitationInput struct {
	Record              Invitation
	RecipientIdentifier identity.Identifier
	MaximumPending      uint64
	Proof               capability.Proof
}

func (InvitationInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationInput(redacted)"))
}
func (InvitationInput) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (InvitationInput) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (s *InvitationService) PrepareSend(ctx context.Context, r InvitationSendRequest) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out = Command{}
			err = ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || !safeID(string(r.ID)) || !safeID(string(r.OrganizationID)) || !safeID(string(r.RecipientUserID)) || !safeID(string(r.RecipientIdentifierID)) || !safeID(r.CorrelationID) || r.OrganizationVersion == 0 {
		return out, ErrInvalidInput
	}
	if _, err = identity.ParseCommandID(string(r.CommandID)); err != nil {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.base.config.MaximumDuration)
	defer cancel()
	for _, id := range []ID{r.ID, r.OrganizationID} {
		if s.base.config.ValidateCanonicalID(bounded, id) != nil {
			return out, ErrInvalidInput
		}
	}
	observed, actor, err := s.base.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	v, err := s.repository.ReadInvitation(bounded, InvitationQuery{Operation: InvitationSend, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, InvitationID: r.ID, RecipientUserID: r.RecipientUserID, RecipientIdentifierID: r.RecipientIdentifierID})
	if err != nil {
		return out, publicError(bounded, err)
	}
	if !validView(View{Organization: v.Organization, Actor: v.Actor}, r.Authentication.TenantID, r.OrganizationID, actor) || v.Actor.Role != RoleOwner {
		return out, ErrForbidden
	}
	if err = s.base.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, InvitationSend, r.CorrelationID); err != nil {
		return out, err
	}
	if observed.ValidateAt(s.base.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	if bounded.Err() != nil {
		return out, bounded.Err()
	}
	if v.Organization.Version != r.OrganizationVersion {
		return out, ErrConflict
	}
	i := v.RecipientIdentifier
	if v.RecipientUser.Validate(r.Authentication.TenantID) != nil || v.RecipientUser.ID != r.RecipientUserID || v.RecipientUser.Status != identity.StatusActive || i.Validate(r.RecipientUserID) != nil || i.ID != r.RecipientIdentifierID || i.Kind != identity.IdentifierEmail || !i.Verified {
		return out, ErrForbidden
	}
	if v.Target.Active {
		return out, ErrConflict
	}
	if v.PendingCount >= s.config.MaximumPending {
		return out, ErrLimit
	}
	expires := s.base.config.Clock.Now().UTC().Truncate(time.Second).Add(s.config.Lifetime)
	record := Invitation{ID: r.ID, OrganizationID: r.OrganizationID, TenantID: r.Authentication.TenantID, RecipientUserID: r.RecipientUserID, RecipientIdentifierID: i.ID, RecipientIdentifierVersion: i.Version, CreatedBy: actor, Role: RoleMember, ExpiresAt: expires}
	command := s.base.command(r.CommandID, InvitationSend, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, v.Target, v.RecipientUser, RoleMember)
	command.state.input.Binding.RecordID = string(record.ID)
	command.state.input.Binding.SchemaID = InvitationSend.Descriptor().SchemaID
	command.state.input.Invitation = InvitationInput{Record: record, RecipientIdentifier: i, MaximumPending: s.config.MaximumPending}
	return command, nil
}

// InvitationAcceptRequest supplies the exact invitation, current organization
// and invitation versions and privately held capability. Authentication must
// independently resolve its intended verified recipient; proof is never login.
type InvitationAcceptRequest struct {
	Authentication                         Authentication
	CommandID                              identity.CommandID
	ID, OrganizationID                     ID
	OrganizationVersion, InvitationVersion uint64
	Proof                                  capability.Proof
	CorrelationID                          string
}

func (InvitationAcceptRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationAcceptRequest(redacted)"))
}
func (InvitationAcceptRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (InvitationAcceptRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// PrepareAccept verifies but never consumes. Native execution must repeat
// current recipient/session/policy admission and atomically consume the shared
// capability with invitation, membership, scoped authority, audit and events.
func (s *InvitationService) PrepareAccept(ctx context.Context, r InvitationAcceptRequest) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out = Command{}
			err = ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || !safeID(string(r.ID)) || !safeID(string(r.OrganizationID)) || !safeID(r.CorrelationID) || r.OrganizationVersion == 0 || r.InvitationVersion == 0 {
		return out, ErrInvalidInput
	}
	if _, err = identity.ParseCommandID(string(r.CommandID)); err != nil {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.base.config.MaximumDuration)
	defer cancel()
	for _, id := range []ID{r.ID, r.OrganizationID} {
		if s.base.config.ValidateCanonicalID(bounded, id) != nil {
			return out, ErrInvalidInput
		}
	}
	observed, actor, err := s.base.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	v, err := s.repository.ReadInvitation(bounded, InvitationQuery{Operation: InvitationAccept, TenantID: r.Authentication.TenantID, ActorID: actor, RecipientUserID: actor, OrganizationID: r.OrganizationID, InvitationID: r.ID})
	if err != nil {
		return out, publicError(bounded, err)
	}
	i := v.Record.Invitation
	if !validInvitation(i, r.Authentication.TenantID, r.OrganizationID) || i.ID != r.ID || i.RecipientUserID != actor || !v.Organization.Active || v.Organization.TenantID != r.Authentication.TenantID || v.Organization.ID != r.OrganizationID || v.Organization.Version == 0 {
		return out, ErrForbidden
	}
	if err = s.base.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, InvitationAccept, r.CorrelationID); err != nil {
		return out, err
	}
	if i.Status == InvitationAccepted || v.Target.Active {
		return out, ErrConflict
	}
	if i.Status != InvitationPending || !s.base.config.Clock.Now().Before(i.ExpiresAt) {
		return out, ErrForbidden
	}
	if i.Version != r.InvitationVersion || v.Organization.Version != r.OrganizationVersion {
		return out, ErrConflict
	}
	identifier := v.RecipientIdentifier
	if v.RecipientUser.Validate(r.Authentication.TenantID) != nil || v.RecipientUser.ID != actor || v.RecipientUser.Status != identity.StatusActive || identifier.Validate(actor) != nil || identifier.ID != i.RecipientIdentifierID || identifier.Version != i.RecipientIdentifierVersion || identifier.Kind != identity.IdentifierEmail || !identifier.Verified {
		return out, ErrForbidden
	}
	grant, e := s.verifier.Verify(bounded, r.Proof, capability.Purpose(InvitationAccept), s.config.Audience)
	if e != nil {
		if bounded.Err() != nil {
			return out, bounded.Err()
		}
		return out, ErrForbidden
	}
	p := grant.Payload()
	expected := map[string]string{"organization.id": string(i.OrganizationID), "organization.invitation-version": strconv.FormatUint(i.Version, 10), "organization.role": string(RoleMember), "organization.recipient-identifier": string(i.RecipientIdentifierID), "organization.recipient-identifier-version": strconv.FormatUint(i.RecipientIdentifierVersion, 10)}
	if p.Bearer || p.Subject != string(actor) || p.Tenant != string(r.Authentication.TenantID) || p.Resource != string(i.ID) || p.Operation != string(InvitationAccept) || p.MaxUses != 1 || len(p.Audiences) != 1 || p.Audiences[0] != s.config.Audience || !p.ExpiresAt.Equal(i.ExpiresAt) || len(p.Caveats) != len(expected) {
		return out, ErrForbidden
	}
	for key, value := range expected {
		if p.Caveats[key] != value {
			return out, ErrForbidden
		}
	}
	if bounded.Err() != nil {
		return out, bounded.Err()
	}
	if observed.ValidateAt(s.base.config.Clock.Now()) != nil || !s.base.config.Clock.Now().Before(i.ExpiresAt) {
		return out, ErrForbidden
	}
	command := s.base.command(r.CommandID, InvitationAccept, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, v.Target, v.RecipientUser, RoleMember)
	command.state.input.Binding.RecordID = string(i.ID)
	command.state.input.Binding.SchemaID = InvitationAccept.Descriptor().SchemaID
	command.state.input.Invitation = InvitationInput{Record: i, RecipientIdentifier: identifier, MaximumPending: s.config.MaximumPending, Proof: r.Proof}
	return command, nil
}

func validInvitation(i Invitation, tenant identity.TenantID, org ID) bool {
	versionValid := (i.Status == InvitationPending || i.Status == InvitationExpired) && i.Version == 1 || (i.Status == InvitationAccepted || i.Status == InvitationCancelled) && i.Version == 2
	return safeID(string(i.ID)) && i.TenantID == tenant && i.OrganizationID == org && safeID(string(i.RecipientUserID)) && safeID(string(i.RecipientIdentifierID)) && i.RecipientIdentifierVersion > 0 && safeID(string(i.CreatedBy)) && i.Role == RoleMember && versionValid && !i.ExpiresAt.IsZero() && i.ExpiresAt.Equal(i.ExpiresAt.UTC().Truncate(time.Second))
}

// InvitationReadRequest selects owner-only safe metadata. Get requires ID and
// zero pagination; List requires no ID, Limit1..100 and an exclusive invitation
// ID cursor in bytewise C order. Pages are current, not retained snapshots.
type InvitationReadRequest struct {
	Authentication     Authentication
	OrganizationID, ID ID
	Cursor             ID
	Limit              uint32
	CorrelationID      string
}

// Get returns safe delivery/invitation metadata only to a current genuine owner.
// It never reveals the canonical address, bearer proof or encrypted custody.
func (s *InvitationService) Get(ctx context.Context, r InvitationReadRequest) (out InvitationDelivery, err error) {
	defer func() {
		if recover() != nil {
			out = InvitationDelivery{}
			err = ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || !safeID(string(r.ID)) || !safeID(string(r.OrganizationID)) || !safeID(r.CorrelationID) || r.Cursor != "" || r.Limit != 0 {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.base.config.MaximumDuration)
	defer cancel()
	for _, id := range []ID{r.ID, r.OrganizationID} {
		if s.base.config.ValidateCanonicalID(bounded, id) != nil {
			return out, ErrInvalidInput
		}
	}
	observed, actor, err := s.base.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	v, err := s.repository.ReadInvitation(bounded, InvitationQuery{Operation: InvitationGet, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, InvitationID: r.ID})
	if err != nil {
		return out, publicError(bounded, err)
	}
	if !validView(View{Organization: v.Organization, Actor: v.Actor}, r.Authentication.TenantID, r.OrganizationID, actor) || v.Actor.Role != RoleOwner {
		return out, ErrForbidden
	}
	if err = s.base.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, InvitationGet, r.CorrelationID); err != nil {
		return out, err
	}
	if !validInvitation(v.Record.Invitation, r.Authentication.TenantID, r.OrganizationID) || v.Record.Invitation.ID != r.ID || !validInvitationDelivery(v.Record) {
		return out, ErrUnavailable
	}
	if bounded.Err() != nil {
		return out, bounded.Err()
	}
	if observed.ValidateAt(s.base.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	return projectInvitationExpiry(v.Record, s.base.config.Clock.Now()), nil
}

// List returns an independently owned, bounded page of owner-only metadata.
// Actor removal/current policy is rechecked on every request, without caching.
func (s *InvitationService) List(ctx context.Context, r InvitationReadRequest) (out InvitationPage, err error) {
	defer func() {
		if recover() != nil {
			out = InvitationPage{}
			err = ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || r.ID != "" || !safeID(string(r.OrganizationID)) || !safeID(r.CorrelationID) || r.Limit < 1 || r.Limit > 100 || r.Cursor != "" && !safeID(string(r.Cursor)) {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.base.config.MaximumDuration)
	defer cancel()
	if s.base.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil {
		return out, ErrInvalidInput
	}
	if r.Cursor != "" && s.base.config.ValidateCanonicalID(bounded, r.Cursor) != nil {
		return out, ErrInvalidInput
	}
	observed, actor, err := s.base.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	v, err := s.repository.ListInvitations(bounded, InvitationQuery{Operation: InvitationList, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, Cursor: r.Cursor, Limit: r.Limit})
	if err != nil {
		return out, publicError(bounded, err)
	}
	if !validView(View{Organization: v.Organization, Actor: v.Actor}, r.Authentication.TenantID, r.OrganizationID, actor) || v.Actor.Role != RoleOwner {
		return out, ErrForbidden
	}
	if err = s.base.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, InvitationList, r.CorrelationID); err != nil {
		return out, err
	}
	if len(v.Invitations) > int(r.Limit) {
		return out, ErrUnavailable
	}
	for n, item := range v.Invitations {
		if !validInvitation(item.Invitation, r.Authentication.TenantID, r.OrganizationID) || !validInvitationDelivery(item) || item.Invitation.ID <= r.Cursor || n > 0 && v.Invitations[n-1].Invitation.ID >= item.Invitation.ID {
			return out, ErrUnavailable
		}
	}
	if v.NextCursor != "" && (len(v.Invitations) != int(r.Limit) || v.NextCursor != v.Invitations[len(v.Invitations)-1].Invitation.ID) {
		return out, ErrUnavailable
	}
	if bounded.Err() != nil {
		return out, bounded.Err()
	}
	now := s.base.config.Clock.Now()
	if observed.ValidateAt(now) != nil {
		return out, ErrForbidden
	}
	v.Invitations = append([]InvitationDelivery(nil), v.Invitations...)
	for n, item := range v.Invitations {
		v.Invitations[n] = projectInvitationExpiry(item, now)
	}
	return v, nil
}

func validInvitationDelivery(i InvitationDelivery) bool {
	// Durable invitation creation includes its one delivery intent atomically;
	// delivery owns these closed state values and16..128 printable ASCII IDs.
	if len(i.EffectID) < 16 || len(i.EffectID) > 128 || i.State < delivery.StateQueued || i.State > delivery.StateTransientFailure {
		return false
	}
	for _, b := range []byte(i.EffectID) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func projectInvitationExpiry(i InvitationDelivery, now time.Time) InvitationDelivery {
	if i.Invitation.Status == InvitationPending && !now.Before(i.Invitation.ExpiresAt) {
		i.Invitation.Status = InvitationExpired
	}
	return i
}
