package organization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-authorization/v3/rbac"
	identity "github.com/faustbrian/go-identity"
)

const (
	CreateDynamicRole Operation = "identity.organization.role.create"
	UpdateDynamicRole Operation = "identity.organization.role.update"
	DeleteDynamicRole Operation = "identity.organization.role.delete"
	GetDynamicRole    Operation = "identity.organization.role.get"
	ListDynamicRoles  Operation = "identity.organization.role.list"
	AssignDynamicRole Operation = "identity.organization.role.assign"
	RevokeDynamicRole Operation = "identity.organization.role.revoke"
	CheckPermission   Operation = "identity.organization.permission-check"
)

// Permission registers one exact action/resource type in the deployment's
// immutable custom-permission ceiling. No wildcard or organization-management
// action is admitted: custom roles never confer static owner/admin authority.
type Permission struct {
	ID           string
	Action       authorization.Action
	ResourceType authorization.ResourceType
}

// DynamicRoleConfig selects the direct-member custom-role profile. Zero disables
// it. MaximumRoles bounds retained role identities per organization (1..100),
// including deleted tombstones, so delete/create churn cannot grow storage.
// Catalog is copied at construction, has 1..128 distinct entries, and is part
// of durable command identity. Changing it requires a deployment policy epoch.
// Team-derived permissions and custom management permissions are unsupported.
type DynamicRoleConfig struct {
	Version, MaximumRoles uint64
	Catalog               []Permission
}

// Validate accepts the disabled zero policy or a bounded complete catalog.
func (c DynamicRoleConfig) Validate() error {
	if c.Version == 0 && c.MaximumRoles == 0 && len(c.Catalog) == 0 {
		return nil
	}
	if c.Version == 0 || c.MaximumRoles < 1 || c.MaximumRoles > 100 || len(c.Catalog) < 1 || len(c.Catalog) > 128 {
		return ErrInvalidInput
	}
	seen := map[string]bool{}
	for _, p := range c.Catalog {
		if !safeID(p.ID) || !safeID(string(p.Action)) || !safeID(string(p.ResourceType)) || strings.ContainsAny(string(p.Action)+string(p.ResourceType), "*?") || strings.HasPrefix(string(p.Action), "identity.") || seen[p.ID] {
			return ErrInvalidInput
		}
		seen[p.ID] = true
	}
	return nil
}

// Fingerprint identifies this complete immutable policy, not a source revision.
func (c DynamicRoleConfig) Fingerprint() string {
	wire, _ := json.Marshal(c)
	h := sha256.Sum256(wire)
	return hex.EncodeToString(h[:])
}
func (c DynamicRoleConfig) clone() DynamicRoleConfig { c.Catalog = slices.Clone(c.Catalog); return c }

// RoleStatement references only registered permissions, an exact resource ID,
// and Allow or Deny. Conditions, wildcards and team inheritance are unselected.
type RoleStatement struct {
	PermissionID string
	ResourceID   authorization.ResourceID
	Effect       authorization.Outcome
}

// DynamicRole is a current bounded custom role snapshot, never a static role.
// Updating replaces all statements immediately for every current binding;
// deleting terminally retires its ID and denies all of its bindings.
type DynamicRole struct {
	ID, OrganizationID ID
	TenantID           identity.TenantID
	Name               string
	Version            uint64
	Statements         []RoleStatement
}

// RoleBinding binds one role to an exact current organization membership epoch.
// Removal/readmission or any static-role transition invalidates old bindings.
// Active describes the stored assignment state, not independent permission:
// current active membership and matching OrganizationMemberVersion still apply.
type RoleBinding struct {
	RoleID, OrganizationID             ID
	TenantID                           identity.TenantID
	UserID                             identity.UserID
	Version, OrganizationMemberVersion uint64
	Active                             bool
}

// ValidateRoleStatements rejects unknown or ambiguous statements before storage
// and again before evaluation. Empty statements intentionally grant nothing.
func ValidateRoleStatements(c DynamicRoleConfig, statements []RoleStatement) error {
	if c.Validate() != nil || c.Version == 0 || len(statements) > 64 {
		return ErrInvalidInput
	}
	seen := map[string]bool{}
	for _, s := range statements {
		registered := false
		for _, p := range c.Catalog {
			if p.ID == s.PermissionID {
				registered = true
				break
			}
		}
		key := s.PermissionID + "\x00" + string(s.ResourceID) + "\x00" + strconv.Itoa(int(s.Effect))
		if !registered || !safeID(string(s.ResourceID)) || strings.ContainsAny(string(s.ResourceID), "*?") || s.Effect != authorization.Allow && s.Effect != authorization.Deny || seen[key] {
			return ErrInvalidInput
		}
		seen[key] = true
	}
	// identity.FeatureValue's public text contract caps each original command
	// field at 8192 bytes; retain the exact statements as one bounded field.
	wire, _ := json.Marshal(statements)
	if len(wire) > 8192 {
		return ErrInvalidInput
	}
	return nil
}

// DynamicRoleRequest replaces Name/Statements for create/update. Delete accepts
// neither replacement field and retires all bindings without reassignment.
// RoleVersion is zero only for create; OrganizationVersion must always match.
type DynamicRoleRequest struct {
	Authentication                   Authentication
	CommandID                        identity.CommandID
	OrganizationID, RoleID           ID
	OrganizationVersion, RoleVersion uint64
	Name, CorrelationID              string
	Statements                       []RoleStatement
}

// RoleBindingRequest assigns/revokes one direct role for an active member.
// BindingVersion is zero for first assignment, otherwise the current tombstone
// or live version; all supplied organization, role and member epochs must match.
type RoleBindingRequest struct {
	Authentication                                                              Authentication
	CommandID                                                                   identity.CommandID
	OrganizationID, RoleID                                                      ID
	UserID                                                                      identity.UserID
	OrganizationVersion, RoleVersion, OrganizationMemberVersion, BindingVersion uint64
	CorrelationID                                                               string
}

// DynamicRoleReadRequest selects one exact role or an exclusive ID-keyset page.
// Reads require current static owner/admin authority. List requires Limit 1..100
// and empty RoleID/TargetUserID; Get requires RoleID, zero Limit and empty Cursor.
// Get's optional TargetUserID returns that exact organization membership and
// its absent/live/tombstone RoleBinding, including versions for a fresh manager.
// Removed membership state remains explicit; a stored binding is never authority.
type DynamicRoleReadRequest struct {
	Authentication         Authentication
	OrganizationID, RoleID ID
	TargetUserID           identity.UserID
	Cursor                 string
	Limit                  uint32
	CorrelationID          string
}

// PermissionCheckRequest checks the authenticated member's direct custom roles,
// never another subject. OrganizationVersion is a required current policy fence.
// Static roles grant management only, not implicit application-resource access.
type PermissionCheckRequest struct {
	Authentication      Authentication
	OrganizationID      ID
	OrganizationVersion uint64
	Action              authorization.Action
	ResourceType        authorization.ResourceType
	ResourceID          authorization.ResourceID
	CorrelationID       string
}

func dynamicRoleMutation(op Operation) bool {
	return op == CreateDynamicRole || op == UpdateDynamicRole || op == DeleteDynamicRole || op == AssignDynamicRole || op == RevokeDynamicRole
}

// PrepareCreateDynamicRole freezes a new role without reserving or persisting it.
func (s *Service) PrepareCreateDynamicRole(ctx context.Context, r DynamicRoleRequest) (Command, error) {
	return s.prepareDynamicRole(ctx, r, RoleBindingRequest{}, CreateDynamicRole)
}

// PrepareUpdateDynamicRole freezes a complete replacement at exact role/organization epochs.
func (s *Service) PrepareUpdateDynamicRole(ctx context.Context, r DynamicRoleRequest) (Command, error) {
	return s.prepareDynamicRole(ctx, r, RoleBindingRequest{}, UpdateDynamicRole)
}

// PrepareDeleteDynamicRole freezes terminal retirement, including all effective bindings.
func (s *Service) PrepareDeleteDynamicRole(ctx context.Context, r DynamicRoleRequest) (Command, error) {
	return s.prepareDynamicRole(ctx, r, RoleBindingRequest{}, DeleteDynamicRole)
}

// PrepareAssignDynamicRole freezes a direct grant for one exact active membership.
func (s *Service) PrepareAssignDynamicRole(ctx context.Context, r RoleBindingRequest) (Command, error) {
	return s.prepareDynamicRole(ctx, DynamicRoleRequest{}, r, AssignDynamicRole)
}

// PrepareRevokeDynamicRole freezes removal of one exact current direct binding.
func (s *Service) PrepareRevokeDynamicRole(ctx context.Context, r RoleBindingRequest) (Command, error) {
	return s.prepareDynamicRole(ctx, DynamicRoleRequest{}, r, RevokeDynamicRole)
}

func (s *Service) prepareDynamicRole(ctx context.Context, r DynamicRoleRequest, b RoleBindingRequest, op Operation) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	binding := op == AssignDynamicRole || op == RevokeDynamicRole
	if binding {
		r = DynamicRoleRequest{Authentication: b.Authentication, CommandID: b.CommandID, OrganizationID: b.OrganizationID, RoleID: b.RoleID, OrganizationVersion: b.OrganizationVersion, RoleVersion: b.RoleVersion, CorrelationID: b.CorrelationID}
	}
	if s == nil || ctx == nil || s.config.DynamicRoles.Version == 0 || !safeID(string(r.OrganizationID)) || !safeID(string(r.RoleID)) || Role(r.RoleID).Valid() || !safeID(r.CorrelationID) || r.OrganizationVersion == 0 || r.OrganizationVersion == ^uint64(0) || r.RoleVersion == ^uint64(0) || op != CreateDynamicRole && r.RoleVersion == 0 {
		return out, ErrInvalidInput
	}
	if _, e := identity.ParseCommandID(string(r.CommandID)); e != nil {
		return out, ErrInvalidInput
	}
	if op == CreateDynamicRole || op == UpdateDynamicRole {
		if !boundedText(r.Name, 256) || ValidateRoleStatements(s.config.DynamicRoles, r.Statements) != nil || op == CreateDynamicRole && r.RoleVersion != 0 {
			return out, ErrInvalidInput
		}
	} else if r.Name != "" || len(r.Statements) != 0 {
		return out, ErrInvalidInput
	}
	if binding && (!safeID(string(b.UserID)) || b.OrganizationMemberVersion == 0 || b.BindingVersion == ^uint64(0) || op == RevokeDynamicRole && b.BindingVersion == 0) {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil || s.config.ValidateCanonicalID(bounded, r.RoleID) != nil {
		return out, ErrInvalidInput
	}
	observed, actor, e := s.authenticate(bounded, r.Authentication)
	if e != nil {
		return out, e
	}
	v, e := s.repository.Read(bounded, Query{Operation: op, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, DynamicRoleID: r.RoleID, TargetID: b.UserID})
	if e != nil {
		return out, publicError(bounded, e)
	}
	if !validView(v, r.Authentication.TenantID, r.OrganizationID, actor) || v.Actor.Role != RoleOwner && v.Actor.Role != RoleAdministrator {
		return out, ErrForbidden
	}
	if e = s.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, op, r.CorrelationID); e != nil {
		return out, e
	}
	if v.Organization.Version != r.OrganizationVersion || v.DynamicRole.Version != r.RoleVersion {
		return out, ErrConflict
	}
	user := identity.User{ID: actor, TenantID: r.Authentication.TenantID}
	if binding {
		if !v.Target.Active || v.Target.UserID != b.UserID || v.Target.TenantID != r.Authentication.TenantID || v.Target.OrganizationID != r.OrganizationID || v.TargetUser.Validate(r.Authentication.TenantID) != nil || v.TargetUser.ID != b.UserID || v.TargetUser.Status != identity.StatusActive {
			return out, ErrForbidden
		}
		if v.Target.Version != b.OrganizationMemberVersion || v.RoleBinding.Version != b.BindingVersion {
			return out, ErrConflict
		}
		current := v.RoleBinding.Active && v.RoleBinding.OrganizationMemberVersion == v.Target.Version
		if op == AssignDynamicRole && current {
			return out, ErrConflict
		}
		if op == RevokeDynamicRole && !current {
			return out, ErrForbidden
		}
		user = v.TargetUser
	} else if op != DeleteDynamicRole {
		v.DynamicRole.Name = strings.Clone(r.Name)
		v.DynamicRole.Statements = slices.Clone(r.Statements)
	}
	if op != CreateDynamicRole && op != UpdateDynamicRole {
		v.DynamicRole.Statements = nil
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	if e = bounded.Err(); e != nil {
		return out, e
	}
	out = s.command(r.CommandID, op, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, v.Target, user, "")
	out.state.input.Binding.SchemaID = op.Descriptor().SchemaID
	out.state.input.DynamicRole = v.DynamicRole
	out.state.input.RoleBinding = v.RoleBinding
	out.state.input.DynamicRoles = s.config.DynamicRoles.clone()
	return out, nil
}

// GetDynamicRole returns one current custom role after late authority revalidation.
func (s *Service) GetDynamicRole(ctx context.Context, r DynamicRoleReadRequest) (View, error) {
	return s.readDynamicRoles(ctx, r, GetDynamicRole)
}

// ListDynamicRoles returns only current custom roles, not the closed static Role constants.
func (s *Service) ListDynamicRoles(ctx context.Context, r DynamicRoleReadRequest) (View, error) {
	return s.readDynamicRoles(ctx, r, ListDynamicRoles)
}
func (s *Service) readDynamicRoles(ctx context.Context, r DynamicRoleReadRequest, op Operation) (out View, err error) {
	defer func() {
		if recover() != nil {
			out, err = View{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || s.config.DynamicRoles.Version == 0 || !safeID(string(r.OrganizationID)) || !safeID(r.CorrelationID) || op == GetDynamicRole && (!safeID(string(r.RoleID)) || r.Limit != 0 || r.Cursor != "" || r.TargetUserID != "" && !safeID(string(r.TargetUserID))) || op == ListDynamicRoles && (r.RoleID != "" || r.TargetUserID != "" || r.Limit < 1 || r.Limit > 100 || r.Cursor != "" && !safeID(r.Cursor)) {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil || r.RoleID != "" && s.config.ValidateCanonicalID(bounded, r.RoleID) != nil {
		return out, ErrInvalidInput
	}
	_, actor, e := s.authenticate(bounded, r.Authentication)
	if e != nil {
		return out, e
	}
	q := Query{Operation: op, TenantID: r.Authentication.TenantID, OrganizationID: r.OrganizationID, ActorID: actor, DynamicRoleID: r.RoleID, TargetID: r.TargetUserID, RoleCursor: r.Cursor, Limit: r.Limit}
	v, e := s.repository.Read(bounded, q)
	if e != nil {
		return out, publicError(bounded, e)
	}
	if !validView(v, q.TenantID, q.OrganizationID, actor) || v.Actor.Role != RoleOwner && v.Actor.Role != RoleAdministrator {
		return out, ErrForbidden
	}
	if e = s.authorize(bounded, actor, q.TenantID, q.OrganizationID, v.Organization.Version, op, r.CorrelationID); e != nil {
		return out, e
	}
	fresh, e := s.refreshRoleView(bounded, r.Authentication, q, v)
	if e != nil {
		return out, e
	}
	if op == GetDynamicRole {
		if !validDynamicRole(fresh.DynamicRole, q.TenantID, q.OrganizationID) || fresh.DynamicRole.ID != r.RoleID || ValidateRoleStatements(s.config.DynamicRoles, fresh.DynamicRole.Statements) != nil {
			return out, ErrForbidden
		}
		if r.TargetUserID != "" && !validRoleBindingView(fresh, q) {
			return out, ErrForbidden
		}
	} else {
		if len(fresh.DynamicRoles) > int(r.Limit) {
			return out, ErrUnavailable
		}
		for i, role := range fresh.DynamicRoles {
			if !validDynamicRole(role, q.TenantID, q.OrganizationID) || string(role.ID) <= r.Cursor || i > 0 && fresh.DynamicRoles[i-1].ID >= role.ID || ValidateRoleStatements(s.config.DynamicRoles, role.Statements) != nil {
				return out, ErrForbidden
			}
		}
		if fresh.NextRoleCursor != "" && (len(fresh.DynamicRoles) != int(r.Limit) || fresh.NextRoleCursor != string(fresh.DynamicRoles[len(fresh.DynamicRoles)-1].ID)) {
			return out, ErrUnavailable
		}
	}
	return fresh, nil
}

func validRoleBindingView(v View, q Query) bool {
	m, b := v.Target, v.RoleBinding
	if m.UserID != q.TargetID || m.TenantID != q.TenantID || m.OrganizationID != q.OrganizationID || !m.Role.Valid() || m.Version == 0 || m.AuthorizationVersion == 0 || v.TargetUser.Validate(q.TenantID) != nil || v.TargetUser.ID != q.TargetID || b.TenantID != q.TenantID || b.OrganizationID != q.OrganizationID || b.RoleID != q.DynamicRoleID || b.UserID != q.TargetID {
		return false
	}
	if b.Version == 0 {
		return b.OrganizationMemberVersion == 0 && !b.Active
	}
	return b.OrganizationMemberVersion > 0
}

func validDynamicRole(r DynamicRole, tenant identity.TenantID, org ID) bool {
	return r.TenantID == tenant && r.OrganizationID == org && safeID(string(r.ID)) && !Role(r.ID).Valid() && boundedText(r.Name, 256) && r.Version > 0
}

func (s *Service) refreshRoleView(ctx context.Context, a Authentication, q Query, v View) (View, error) {
	observed, actor, e := s.authenticate(ctx, a)
	if e != nil {
		return View{}, e
	}
	if actor != q.ActorID {
		return View{}, ErrForbidden
	}
	fresh, e := s.repository.Read(ctx, q)
	if e != nil {
		return View{}, publicError(ctx, e)
	}
	if !validView(fresh, q.TenantID, q.OrganizationID, actor) || fresh.Organization.Version != v.Organization.Version || fresh.Actor != v.Actor || observed.ValidateAt(s.config.Clock.Now()) != nil {
		return View{}, ErrForbidden
	}
	// Repository reads may span several primary statements. Fence the epoch
	// after loading roles so a concurrent update cannot mix an old aggregate
	// snapshot with new statements (or disclose a removed membership).
	fence, e := s.repository.Read(ctx, Query{Operation: Get, TenantID: q.TenantID, OrganizationID: q.OrganizationID, ActorID: actor})
	if e != nil {
		return View{}, publicError(ctx, e)
	}
	if !validView(fence, q.TenantID, q.OrganizationID, actor) || fence.Organization.Version != fresh.Organization.Version || fence.Actor != fresh.Actor || observed.ValidateAt(s.config.Clock.Now()) != nil {
		return View{}, ErrForbidden
	}
	if e = ctx.Err(); e != nil {
		return View{}, e
	}
	return fresh, nil
}

// CheckPermission never caches an allow. A policy callback can veto the check;
// the existing RBAC/deny-overrides engine decides only current exact statements.
// Returned Revision is the organization policy version, not a reusable lease.
func (s *Service) CheckPermission(ctx context.Context, r PermissionCheckRequest) (out authorization.Decision, err error) {
	defer func() {
		if recover() != nil {
			out, err = authorization.Decision{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || s.config.DynamicRoles.Version == 0 || !safeID(string(r.OrganizationID)) || r.OrganizationVersion == 0 || !safeID(r.CorrelationID) || !safeID(string(r.Action)) || !safeID(string(r.ResourceType)) || !safeID(string(r.ResourceID)) {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil {
		return out, ErrInvalidInput
	}
	_, actor, e := s.authenticate(bounded, r.Authentication)
	if e != nil {
		return out, e
	}
	q := Query{Operation: CheckPermission, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, Limit: uint32(s.config.DynamicRoles.MaximumRoles)}
	v, e := s.repository.Read(bounded, q)
	if e != nil {
		return out, publicError(bounded, e)
	}
	if !validView(v, q.TenantID, q.OrganizationID, actor) || v.Organization.Version != r.OrganizationVersion {
		return out, ErrForbidden
	}
	if e = s.authorize(bounded, actor, q.TenantID, q.OrganizationID, v.Organization.Version, CheckPermission, r.CorrelationID); e != nil {
		return out, e
	}
	fresh, e := s.refreshRoleView(bounded, r.Authentication, q, v)
	if e != nil {
		return out, e
	}
	if len(fresh.DynamicRoles) > int(s.config.DynamicRoles.MaximumRoles) {
		return out, ErrForbidden
	}
	for _, role := range fresh.DynamicRoles {
		if !validDynamicRole(role, q.TenantID, q.OrganizationID) {
			return out, ErrForbidden
		}
	}
	request := authorization.Request{Tenant: authorization.TenantID(q.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: r.Action, Resource: authorization.Resource{Type: r.ResourceType, ID: r.ResourceID, Attributes: authorization.Attributes{"organization.id": authorization.StringValue(string(q.OrganizationID)), "organization.policy-version": authorization.StringValue(strconv.FormatUint(r.OrganizationVersion, 10))}}, Environment: authorization.Environment{Time: s.config.Clock.Now()}}
	return evaluateRoles(bounded, s.config.DynamicRoles, fresh.DynamicRoles, request, r.OrganizationVersion)
}

func evaluateRoles(ctx context.Context, c DynamicRoleConfig, roles []DynamicRole, request authorization.Request, version uint64) (authorization.Decision, error) {
	if c.Validate() != nil || c.Version == 0 || len(roles) > int(c.MaximumRoles) {
		return authorization.Decision{}, ErrForbidden
	}
	rs := make([]rbac.Role, 0, len(roles))
	ps := []rbac.Permission{}
	as := make([]rbac.Assignment, 0, len(roles))
	for i, r := range roles {
		if ValidateRoleStatements(c, r.Statements) != nil {
			return authorization.Decision{}, ErrForbidden
		}
		id := rbac.RoleID(r.ID)
		rs = append(rs, rbac.Role{ID: id, Tenant: request.Tenant})
		as = append(as, rbac.Assignment{ID: authorization.PolicyID("binding-" + strconv.Itoa(i)), Subject: request.Subject, RoleID: id, Tenant: request.Tenant})
		for j, s := range r.Statements {
			for _, p := range c.Catalog {
				if p.ID == s.PermissionID {
					ps = append(ps, rbac.Permission{ID: authorization.PolicyID(strconv.Itoa(i) + "-" + strconv.Itoa(j)), RoleID: id, Tenant: request.Tenant, Action: p.Action, ResourceType: p.ResourceType, ResourceID: s.ResourceID, Effect: s.Effect})
					break
				}
			}
		}
	}
	evaluator, e := rbac.New(rs, ps, as, rbac.WithLimits(rbac.Limits{MaxRoles: 100, MaxPermissions: 6400, MaxAssignments: 100, MaxMatches: 6400}))
	if e != nil {
		return authorization.Decision{}, ErrForbidden
	}
	snapshot, e := authorization.NewSnapshot(authorization.Revision(version), authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-direct-roles", Evaluator: evaluator})
	if e != nil {
		return authorization.Decision{}, ErrUnavailable
	}
	engine, e := authorization.NewEngine(snapshot)
	if e != nil {
		return authorization.Decision{}, ErrUnavailable
	}
	decision, e := engine.Decide(ctx, request)
	if e != nil {
		return authorization.Decision{}, publicError(ctx, e)
	}
	return decision, nil
}
