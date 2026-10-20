package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/jackc/pgx/v5"
)

func isDynamicRoleMutation(op organization.Operation) bool {
	return op == organization.CreateDynamicRole || op == organization.UpdateDynamicRole || op == organization.DeleteDynamicRole || isRoleBindingMutation(op)
}
func isRoleBindingMutation(op organization.Operation) bool {
	return op == organization.AssignDynamicRole || op == organization.RevokeDynamicRole
}
func isDynamicRoleOperation(op organization.Operation) bool {
	return isDynamicRoleMutation(op) || op == organization.GetDynamicRole || op == organization.ListDynamicRoles || op == organization.CheckPermission
}

func (s *Service) PrepareCreateDynamicRole(ctx context.Context, r organization.DynamicRoleRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareCreateDynamicRole(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) PrepareUpdateDynamicRole(ctx context.Context, r organization.DynamicRoleRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareUpdateDynamicRole(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) PrepareDeleteDynamicRole(ctx context.Context, r organization.DynamicRoleRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareDeleteDynamicRole(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) PrepareAssignDynamicRole(ctx context.Context, r organization.RoleBindingRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareAssignDynamicRole(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) PrepareRevokeDynamicRole(ctx context.Context, r organization.RoleBindingRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareRevokeDynamicRole(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) GetDynamicRole(ctx context.Context, r organization.DynamicRoleReadRequest) (organization.View, error) {
	if s == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.core.GetDynamicRole(ctx, r)
}
func (s *Service) ListDynamicRoles(ctx context.Context, r organization.DynamicRoleReadRequest) (organization.View, error) {
	if s == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.core.ListDynamicRoles(ctx, r)
}
func (s *Service) CheckPermission(ctx context.Context, r organization.PermissionCheckRequest) (authorization.Decision, error) {
	if s == nil {
		return authorization.Decision{}, organization.ErrInvalidInput
	}
	return s.core.CheckPermission(ctx, r)
}

func decodeRoleStatements(wire string) ([]organization.RoleStatement, error) {
	if len(wire) > 8192 {
		return nil, organization.ErrForbidden
	}
	var statements []organization.RoleStatement
	d := json.NewDecoder(bytes.NewBufferString(wire))
	d.DisallowUnknownFields()
	if d.Decode(&statements) != nil || d.Decode(new(any)) != io.EOF || len(statements) > 64 {
		return nil, organization.ErrForbidden
	}
	return statements, nil
}

func (r *Repository) readDynamicRoles(ctx context.Context, q organization.Query, v organization.View) (organization.View, error) {
	if q.TargetID != "" && q.Operation != organization.GetDynamicRole && !isRoleBindingMutation(q.Operation) {
		return organization.View{}, organization.ErrInvalidInput
	}
	scope, e := OrganizationAuthorityScope(q.TenantID, q.OrganizationID, q.ActorID)
	if e != nil {
		return organization.View{}, e
	}
	store, e := authority.NewAuthorityStore(r.pool.Raw(), r.maximum)
	if e != nil {
		return organization.View{}, organization.ErrUnavailable
	}
	current, e := store.Get(ctx, scope)
	if e != nil {
		return organization.View{}, publicTeamAuthorityError(e)
	}
	if current.Version != v.Actor.AuthorizationVersion {
		return organization.View{}, organization.ErrForbidden
	}
	if q.Operation != organization.CheckPermission && v.Actor.Role != organization.RoleOwner && v.Actor.Role != organization.RoleAdministrator {
		return organization.View{}, organization.ErrForbidden
	}
	if q.Operation == organization.ListDynamicRoles || q.Operation == organization.CheckPermission {
		if q.Limit < 1 || q.Limit > 100 || q.RoleCursor != "" && !scopeID(q.RoleCursor) {
			return organization.View{}, organization.ErrInvalidInput
		}
		rows, e := r.pool.Raw().Query(ctx, `SELECT r.role_id,r.name,r.version::text,r.statements FROM organization.custom_roles r WHERE r.tenant_id=$1 AND r.organization_id=$2 AND r.state='active' AND r.role_id>$3 COLLATE "C" AND ($4 OR EXISTS(SELECT 1 FROM organization.role_bindings b JOIN organization.memberships m USING(tenant_id,organization_id,user_id) WHERE b.tenant_id=r.tenant_id AND b.organization_id=r.organization_id AND b.role_id=r.role_id AND b.user_id=$5 AND b.state='active' AND m.state='active' AND b.organization_member_version=m.version)) ORDER BY r.role_id COLLATE "C" LIMIT $6`, string(q.TenantID), string(q.OrganizationID), q.RoleCursor, q.Operation == organization.ListDynamicRoles, string(q.ActorID), int32(q.Limit+1))
		if e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		defer rows.Close()
		for rows.Next() {
			role := organization.DynamicRole{TenantID: q.TenantID, OrganizationID: q.OrganizationID}
			var version, wire string
			if e = rows.Scan(&role.ID, &role.Name, &version, &wire); e != nil {
				return organization.View{}, organization.ErrUnavailable
			}
			if role.Version, e = positive(version); e != nil {
				return organization.View{}, e
			}
			if role.Statements, e = decodeRoleStatements(wire); e != nil {
				return organization.View{}, e
			}
			if len(v.DynamicRoles) == int(q.Limit) {
				v.NextRoleCursor = string(v.DynamicRoles[len(v.DynamicRoles)-1].ID)
				break
			}
			v.DynamicRoles = append(v.DynamicRoles, role)
		}
		if e = rows.Err(); e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		if q.Operation == organization.CheckPermission && v.NextRoleCursor != "" {
			return organization.View{}, organization.ErrForbidden
		}
		return v, nil
	}
	if !scopeID(string(q.DynamicRoleID)) || organization.Role(q.DynamicRoleID).Valid() {
		return organization.View{}, organization.ErrInvalidInput
	}
	v.DynamicRole = organization.DynamicRole{ID: q.DynamicRoleID, OrganizationID: q.OrganizationID, TenantID: q.TenantID}
	var version, wire, state string
	e = r.pool.Raw().QueryRow(ctx, `SELECT name,version::text,statements,state FROM organization.custom_roles WHERE tenant_id=$1 AND organization_id=$2 AND role_id=$3`, string(q.TenantID), string(q.OrganizationID), string(q.DynamicRoleID)).Scan(&v.DynamicRole.Name, &version, &wire, &state)
	if e != nil {
		if e == pgx.ErrNoRows && q.Operation == organization.CreateDynamicRole {
			return v, nil
		}
		return organization.View{}, storageError(ctx, e)
	}
	if state != "active" {
		if q.Operation == organization.CreateDynamicRole {
			return organization.View{}, organization.ErrConflict
		}
		return organization.View{}, organization.ErrForbidden
	}
	if v.DynamicRole.Version, e = positive(version); e != nil {
		return organization.View{}, e
	}
	if v.DynamicRole.Statements, e = decodeRoleStatements(wire); e != nil {
		return organization.View{}, e
	}
	if isRoleBindingMutation(q.Operation) || q.Operation == organization.GetDynamicRole && q.TargetID != "" {
		if !scopeID(string(q.TargetID)) {
			return organization.View{}, organization.ErrInvalidInput
		}
		v.Target = organization.Member{TenantID: q.TenantID, OrganizationID: q.OrganizationID, UserID: q.TargetID}
		var member, epoch string
		e = r.pool.Raw().QueryRow(ctx, `SELECT role,version::text,authorization_version::text,state='active' FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(q.TenantID), string(q.OrganizationID), string(q.TargetID)).Scan(&v.Target.Role, &member, &epoch, &v.Target.Active)
		if e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		if v.Target.Version, e = positive(member); e != nil {
			return organization.View{}, e
		}
		if v.Target.AuthorizationVersion, e = positive(epoch); e != nil {
			return organization.View{}, e
		}
		v.TargetUser, e = r.directory.Get(ctx, identity.GetUserQuery{TenantID: q.TenantID, UserID: q.TargetID})
		if e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		v.RoleBinding = organization.RoleBinding{TenantID: q.TenantID, OrganizationID: q.OrganizationID, RoleID: q.DynamicRoleID, UserID: q.TargetID}
		e = r.pool.Raw().QueryRow(ctx, `SELECT version::text,organization_member_version::text,state='active' FROM organization.role_bindings WHERE tenant_id=$1 AND organization_id=$2 AND role_id=$3 AND user_id=$4`, string(q.TenantID), string(q.OrganizationID), string(q.DynamicRoleID), string(q.TargetID)).Scan(&version, &member, &v.RoleBinding.Active)
		if e == pgx.ErrNoRows {
			return v, nil
		}
		if e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		if v.RoleBinding.Version, e = positive(version); e != nil {
			return organization.View{}, e
		}
		if v.RoleBinding.OrganizationMemberVersion, e = positive(member); e != nil {
			return organization.View{}, e
		}
	}
	return v, nil
}
func scopeID(s string) bool { return scope(s) }

func (p *Contributor) dynamicRoleFields(x organization.CommandInput) ([]identity.FeatureField, error) {
	if p.config.DynamicRoles.Version == 0 || x.DynamicRoles.Fingerprint() != p.config.DynamicRoles.Fingerprint() || organization.ValidateRoleStatements(p.config.DynamicRoles, x.DynamicRole.Statements) != nil {
		return nil, organization.ErrInvalidInput
	}
	wire, e := json.Marshal(x.DynamicRole.Statements)
	if e != nil {
		return nil, organization.ErrInvalidInput
	}
	return []identity.FeatureField{text("custom-role-id", string(x.DynamicRole.ID)), text("custom-role-name", x.DynamicRole.Name), text("custom-role-statements", string(wire)), text("custom-role-policy", x.DynamicRoles.Fingerprint()), number("custom-role-version", x.DynamicRole.Version), number("binding-version", x.RoleBinding.Version), number("binding-member-version", x.RoleBinding.OrganizationMemberVersion)}, nil
}

func (p *Contributor) decodeDynamicRole(c *nativeCommand, t func(string) string, n func(string) uint64) error {
	bad := organization.ErrInvalidInput
	b := c.spec.Binding
	if p.config.DynamicRoles.Version == 0 || t("custom-role-policy") != p.config.DynamicRoles.Fingerprint() || !scope(t("custom-role-id")) || organization.Role(t("custom-role-id")).Valid() || !boundedTeamName(t("custom-role-name")) || c.org.Version == 0 || c.org.Version == ^uint64(0) || c.actor.Version == 0 || c.actor.AuthorizationVersion == 0 || c.actor.Role != organization.RoleOwner && c.actor.Role != organization.RoleAdministrator || c.role != "" {
		return bad
	}
	statements, e := decodeRoleStatements(t("custom-role-statements"))
	if e != nil || organization.ValidateRoleStatements(p.config.DynamicRoles, statements) != nil {
		return bad
	}
	c.dynamicRole = organization.DynamicRole{ID: organization.ID(t("custom-role-id")), OrganizationID: c.org.ID, TenantID: b.TenantID, Name: t("custom-role-name"), Version: n("custom-role-version"), Statements: statements}
	c.roleBinding = organization.RoleBinding{RoleID: c.dynamicRole.ID, OrganizationID: c.org.ID, TenantID: b.TenantID, UserID: b.UserID, Version: n("binding-version"), OrganizationMemberVersion: n("binding-member-version")}
	if c.dynamicRole.Version == ^uint64(0) || c.roleBinding.Version == ^uint64(0) {
		return bad
	}
	if c.operation == organization.CreateDynamicRole {
		if c.dynamicRole.Version != 0 {
			return bad
		}
	} else if c.dynamicRole.Version == 0 {
		return bad
	}
	if isRoleBindingMutation(c.operation) {
		if len(statements) != 0 || c.target.Version == 0 || c.target.AuthorizationVersion == 0 || !c.target.Role.Valid() || c.user.Validate(b.TenantID) != nil || c.user.Status != identity.StatusActive || c.operation == organization.RevokeDynamicRole && c.roleBinding.Version == 0 || c.roleBinding.Version == 0 && c.roleBinding.OrganizationMemberVersion != 0 || c.roleBinding.Version > 0 && c.roleBinding.OrganizationMemberVersion == 0 {
			return bad
		}
		// Member is reconstructed active only after source-owned target admission.
		c.target.Active = true
	} else if c.target.Version != 0 || c.target.AuthorizationVersion != 0 || c.target.Role != "" || c.user.Version != 0 || c.user.Status != "" || b.UserID != identity.UserID(b.ActorID) || c.roleBinding.Version != 0 || c.roleBinding.OrganizationMemberVersion != 0 || c.operation == organization.DeleteDynamicRole && len(statements) != 0 {
		return bad
	}
	return nil
}

func (p *Contributor) mutateDynamicRole(ctx context.Context, w kernel.Work, c nativeCommand) error {
	b := c.spec.Binding
	var version, state string
	rows, e := w.Query(ctx, `SELECT version::text,state FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 FOR UPDATE`, string(b.TenantID), string(c.org.ID))
	if e = one(rows, e, &version, &state); e != nil {
		return e
	}
	if state != "active" {
		return identity.ForbiddenError{}
	}
	if version != strconv.FormatUint(c.org.Version, 10) {
		return identity.ConflictError{}
	}
	actor, e := readMember(ctx, w, b.TenantID, c.org.ID, identity.UserID(b.ActorID))
	if e != nil {
		return e
	}
	if actor != c.actor || !actor.Active || actor.Role != organization.RoleOwner && actor.Role != organization.RoleAdministrator {
		return identity.ForbiddenError{}
	}
	scope, e := OrganizationAuthorityScope(b.TenantID, c.org.ID, actor.UserID)
	if e != nil {
		return e
	}
	if e = authority.RequireAuthority(ctx, w, scope, actor.AuthorizationVersion, p.config.Session.MaximumDuration); e != nil {
		return authorityError(e)
	}
	role := c.dynamicRole
	wire, _ := json.Marshal(role.Statements)
	if c.operation == organization.CreateDynamicRole {
		var count int64
		var duplicate bool
		rows, e = w.Query(ctx, `SELECT count(*),coalesce(bool_or(role_id=$3),false) FROM organization.custom_roles WHERE tenant_id=$1 AND organization_id=$2`, string(b.TenantID), string(c.org.ID), string(role.ID))
		if e = one(rows, e, &count, &duplicate); e != nil {
			return e
		}
		if duplicate {
			return identity.ConflictError{}
		}
		if count < 0 || uint64(count) >= p.config.DynamicRoles.MaximumRoles {
			return identity.ForbiddenError{}
		}
		_, e = w.Exec(ctx, `INSERT INTO organization.custom_roles(tenant_id,organization_id,role_id,name,version,state,statements) VALUES($1,$2,$3,$4,1,'active',$5)`, string(b.TenantID), string(c.org.ID), string(role.ID), role.Name, string(wire))
		if e != nil {
			return e
		}
	} else {
		var name, stored string
		rows, e = w.Query(ctx, `SELECT name,version::text,state,statements FROM organization.custom_roles WHERE tenant_id=$1 AND organization_id=$2 AND role_id=$3 FOR UPDATE`, string(b.TenantID), string(c.org.ID), string(role.ID))
		if e = one(rows, e, &name, &version, &state, &stored); e != nil {
			return e
		}
		if state != "active" {
			return identity.ForbiddenError{}
		}
		if version != strconv.FormatUint(role.Version, 10) {
			return identity.ConflictError{}
		}
		if isRoleBindingMutation(c.operation) {
			if e = p.mutateRoleBinding(ctx, w, c); e != nil {
				return e
			}
		} else {
			if c.operation == organization.UpdateDynamicRole && name == role.Name && stored == string(wire) {
				return identity.ConflictError{}
			}
			next := "active"
			if c.operation == organization.DeleteDynamicRole {
				next = "deleted"
				wire = []byte("[]")
				role.Name = name
			}
			n, e := w.Exec(ctx, `UPDATE organization.custom_roles SET name=$4,statements=$5,state=$6,version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND role_id=$3 AND version=$7::numeric AND version<18446744073709551615 AND state='active'`, string(b.TenantID), string(c.org.ID), string(role.ID), role.Name, string(wire), next, version)
			if e != nil {
				return e
			}
			if n != 1 {
				return identity.ConflictError{}
			}
		}
	}
	n, e := w.Exec(ctx, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND version<18446744073709551615 AND state='active'`, string(b.TenantID), string(c.org.ID), strconv.FormatUint(c.org.Version, 10))
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *Contributor) mutateRoleBinding(ctx context.Context, w kernel.Work, c nativeCommand) error {
	b := c.spec.Binding
	target, e := readMember(ctx, w, b.TenantID, c.org.ID, b.UserID)
	if e != nil {
		return e
	}
	if !target.Active || target != c.target {
		return identity.ForbiddenError{}
	}
	scope, e := OrganizationAuthorityScope(b.TenantID, c.org.ID, b.UserID)
	if e != nil {
		return e
	}
	if e = authority.RequireAuthority(ctx, w, scope, target.AuthorizationVersion, p.config.Session.MaximumDuration); e != nil {
		return authorityError(e)
	}
	var version, member string
	var active bool
	rows, e := w.Query(ctx, `SELECT version::text,organization_member_version::text,state='active' FROM organization.role_bindings WHERE tenant_id=$1 AND organization_id=$2 AND role_id=$3 AND user_id=$4 FOR UPDATE`, string(b.TenantID), string(c.org.ID), string(c.dynamicRole.ID), string(b.UserID))
	if e != nil {
		return e
	}
	found := rows.Next()
	if found {
		e = rows.Scan(&version, &member, &active)
	}
	if rowErr := rows.Err(); e == nil {
		e = rowErr
	}
	rows.Close()
	if e != nil {
		return e
	}
	if found && (version != strconv.FormatUint(c.roleBinding.Version, 10) || member != strconv.FormatUint(c.roleBinding.OrganizationMemberVersion, 10)) || !found && c.roleBinding.Version != 0 {
		return identity.ConflictError{}
	}
	current := active && member == strconv.FormatUint(target.Version, 10)
	if c.operation == organization.AssignDynamicRole && current {
		return identity.ConflictError{}
	}
	if c.operation == organization.RevokeDynamicRole && !current {
		return identity.ForbiddenError{}
	}
	next := "active"
	if c.operation == organization.RevokeDynamicRole {
		next = "removed"
	}
	n, e := w.Exec(ctx, `INSERT INTO organization.role_bindings(tenant_id,organization_id,role_id,user_id,version,organization_member_version,state) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7) ON CONFLICT(tenant_id,organization_id,role_id,user_id) DO UPDATE SET version=EXCLUDED.version,organization_member_version=EXCLUDED.organization_member_version,state=EXCLUDED.state WHERE organization.role_bindings.version=$8::numeric`, string(b.TenantID), string(c.org.ID), string(c.dynamicRole.ID), string(b.UserID), strconv.FormatUint(c.roleBinding.Version+1, 10), strconv.FormatUint(target.Version, 10), next, strconv.FormatUint(c.roleBinding.Version, 10))
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	projection, e := authority.AdvanceAuthority(ctx, w, scope, target.AuthorizationVersion, p.config.Session.MaximumDuration)
	if e != nil {
		return authorityError(e)
	}
	_, e = w.Exec(ctx, `UPDATE organization.memberships SET authorization_version=$4::numeric WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(b.TenantID), string(c.org.ID), string(b.UserID), strconv.FormatUint(projection.Version, 10))
	return e
}
