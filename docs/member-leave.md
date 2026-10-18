# Explicit member self-leave

The selected `identity.organization.member.leave` operation is available as
`PrepareLeaveMember(ctx, LeaveRequest)` in core and
`PrepareLeaveMember(ctx, LeaveRequest, trustedCanonicalClientIP)` in the native
adapter, followed by the existing `Execute`/`Recovery` boundary.

`LeaveRequest` contains authentication, original random command identity,
explicit organization ID, exact `OrganizationVersion` and correlation ID. There
is no target or role parameter: only the authenticated active human member can
leave. Preparation captures that member's exact version and scoped authority;
execution checks the same current session, credential, organization and member
under the existing protected transaction. Stale epochs conflict, missing or
foreign authority denies, and current action policy is required. Preserve the
same prepared command for bounded retries, not a newly prepared observation.

The selected closed static-role profile treats owners as its recovery-capable
administrators. At least one active owner must survive. Leave, administrative
removal and ownership transfer share tenant/organization serialization, so
competing transitions cannot remove the final recovery owner. Broader custom
recovery roles remain unselected; this is not complete M22 role management.

A successful leave advances the organization policy epoch, membership version
and organization-scoped subject authority and retains a removal tombstone.
It does not alter global directory, password, session or independent
organization-owned credential authority. Organization/team reads deny after
leave. Readmission advances the retained member version again; team bindings
remain attached to the old exact membership version and do not revive.

The operation catalog's distinct self-leave command maps to the existing
security-event catalog's protected `identity.organization.remove_member` audit
effect and `membership.removed.v1` lifecycle effect. This is effect reuse, not
administrative authorization reuse. Both effects, the tombstone and epoch
advances commit atomically through the sole identity coordinator; rollback
leaves them unchanged. Installed migration bytes and legacy command fields
are unchanged; no new organization migration is necessary.

Recovery reveals only original metadata and always applies current session and
current membership disclosure policy. A successful departure therefore denies
its former member recovery, even with another legitimate global session. An
unknown acknowledgement remains unknown to that caller; it is not permission
to re-execute under another command ID. Following independently authorized
readmission, the same original recovery scope may disclose the historical
committed receipt without removing the new membership or renewing old authority.
Active-organization selection, HTTP, dynamic roles and organization-key issuance
are not selected by this profile.
