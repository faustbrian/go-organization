package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// UpdateMember admits one original key for an exact-version static-role change.
// The existing native member owner retains current owner/administrator and
// scoped authority checks, owner transitions, last-owner safety and atomic
// protected effects. Matching retries recover only the original outcome under
// current disclosure policy, including legitimate self-demotion history; they
// never prepare a new mutation, refresh versions or renew original authority.
// Network must be the transport's trusted canonical full client address.
func (s *OperationService) UpdateMember(ctx context.Context, r organization.UpdateMemberOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	fields := []identity.FeatureField{text("id", string(r.OrganizationID)), text("target", string(r.UserID)), text("role", string(r.Role)), number("version", r.OrganizationVersion), number("member-version", r.MemberVersion)}
	return s.state().keyed(ctx, r.Authentication, organization.UpdateMember, r.IdempotencyKey, fields, network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		return service.core.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, UserID: r.UserID, Role: r.Role, OrganizationVersion: r.OrganizationVersion, MemberVersion: r.MemberVersion, CorrelationID: r.CorrelationID})
	})
}
