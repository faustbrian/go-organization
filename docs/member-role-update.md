# Authorized static member-role updates

The callable operation `identity.organization.member.update` uses
`Service.PrepareUpdateMember(ctx, MemberRequest)` in core and
`postgres.Service.PrepareUpdateMember(ctx, MemberRequest, trustedCanonicalClientIP)`
in the native adapter, followed by the existing `Execute`/`Recovery` boundary.
The request selects an explicit organization, active target user, different
static `Role`, exact organization policy epoch and membership version. Keep its
original random command ID and prepared value for bounded retries. Repreparing
changes the session observation and is not an identical keyed retry.

Current owners and administrators may change nonowner roles between `member`
and `administrator`, including their own role. Only owners may assign `owner`
or change an existing owner. The selected static profile already treats owners
as recovery-capable administrators: at least one owner must survive. The same
organization serialization protects role updates, administrative removal,
self-leave and ownership transfer; no separate administrator class is invented.
Unknown roles deny, unchanged roles conflict, and stale exact versions conflict.
The target identity must remain active at its captured directory version.

This is not `owner-transfer`: that separate operation requires its native
operation-bound primary proof, exchanges the authenticated owner's role with
an existing nonowner and conserves the owner count. Static role management
retains the preexisting owner-only ability to grant additional ownership, just
as `PrepareAddMember` can already admit another owner. Dynamic roles,
custom permission statements and the separate permission-check API remain
unselected. Current `Get`/`ListMembers` and existing management operations
observe and enforce the new static role and organization policy version.

## Atomic authority and effects

The target membership version and organization-scoped subject authorization
version each advance once; the organization policy epoch advances once.
Membership stays active and member count stays unchanged. Owner count changes
only when the role crosses the owner boundary. Current session, credential,
actor membership/scoped authority and exact target identity/member authority
are protected through the existing native Coordinator transaction. Concurrent
removal, owner transfer or another role update cannot overwrite a stale view.

Only that subject's scoped authority changes, not global user, password,
session or an independent organization's credential authority (SI-02). Existing
exact-version team bindings become stale, as they do on ownership transfer;
the role update does not manufacture replacement bindings or permissions.
Cache/downstream cascade closure is not claimed by the current primary-backed
profile. The canonical protected `identity.organization.change_member_role`
audit and `membership.role_changed.v1` lifecycle event commit or roll back with
the role/count/version effects. Existing installed schema bytes are sufficient.

## Retries and historical disclosure

Replay returns the original outcome without another role, version, audit or
event effect. A lost COMMIT response remains `Unknown` until the existing
coordinator classifies the exact safe recovery binding on the primary. Persist
that binding before execution; recovery works on a reconstructed service with
current genuine authentication and no code or original prepared command.

Historical disclosure always rechecks current session, active membership,
scoped authority and action/query policy, including after callbacks. Other-target
history requires a current owner or administrator. Exact self-role history
follows the existing owner-transfer disclosure rule: a legitimately demoted
member may recover its own outcome without reacquiring manager privilege, but
cannot prepare a new privileged command. Removal or session withdrawal denies
that disclosure. Neither replay nor recovery renews original execution expiry.

This finite profile is not complete M22 role management or M23 invalidation
qualification and introduces no transport, invitation or domain-claim API.
