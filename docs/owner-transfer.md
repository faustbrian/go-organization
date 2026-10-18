# Selected ownership transfer

The callable operation is `identity.organization.owner-transfer`. The selected
native API follows the existing `PrepareOwnerTransfer` / `Execute` / `Recover`
model rather than inventing a second one-call transaction owner. The root
remains storage-neutral. No HTTP/browser or full M22 completion is claimed.

Set the core's explicit `OwnerTransferAudience` to the native password source's
selected action audience and supply `ContributorConfig.OwnerTransferPrimary`.
Omitting both disables the transfer operation without changing legacy feature
framing. Mismatched startup selection is rejected; session audience is separate.

The operation requires an original signed password reauthentication proof for
this exact tenant, source subject, session/version, action and audience, with
an exclusive maximum age of 15 minutes. This follows the ownership-transfer
row in `REFERENCE_CONFIGURATION.md`'s freshness operation matrix; normal
24-hour session freshness cannot replace that proof. The password owner
authenticates and atomically consumes it in the protected native Work.

This selected single-factor profile also requires independently known-empty
current MFA authority for both the actor and target. Native preparation reads
the real MFA owner's generations after genuine password admission and retains
both in the original keyed command. The MFA owner fences those exact rows in
canonical subject order before mutation and again at final commit. Missing or
enrolled state denies; activation or any generation change after preparation
denies even when the original SFA session remains valid. An MFA-capable transfer
profile is not selected here.

## Scope and disposition

`OwnerTransferRequest` selects an organization, its expected policy epoch,
the source membership version, an existing target user and target membership
version. The source user is always derived from the genuine authenticated
session; it is never a requester-selected actor. Self-transfer, inactive or
foreign membership and an already-owner target are denied. Only a current
owner may transfer, not an administrator.

The planning `SourceMemberID` maps to the authenticated actor's existing
user-keyed membership; no second membership-ID authority is introduced.
`SourceVersion` and `TargetVersion` retain their declared meaning, with an
additional explicit organization policy checkpoint. The existing `StoreResult`
returns the original binding's actor/target IDs and organization feature receipt;
its committed `AfterVersion` is the transferred organization policy epoch.
Use current authenticated member reads for the resulting roles and versions,
not a historical recovery receipt as an authority projection.

The source becomes `RoleMember` and the target becomes `RoleOwner`. Both remain
active. Each membership version and organization-scoped authorization epoch
advances once; the organization policy epoch advances once. Member and owner
counts do not change. Existing other owners are unaffected, so this is not a
single-owner-only schema. Subsequent last-owner removal protection is unchanged.

Exact-version team bindings of either changed membership become stale under
the existing team-admission contract; transfer never manufactures a replacement
team binding or new permissions. Global user, password/session and independent
organization-key authority are not revoked or reassigned (SI-02).

## Durability and recovery

The existing native coordinator protects current session/credential/directory
authority, the organization and both memberships and scoped authorities. No
callback runs under organization locks. Risk, domain changes, protected audit
action `identity.organization.transfer_ownership` and additive lifecycle event
`organization.ownership_transferred.v1` commit or roll back together. The event
is distinct because the selected catalogs do not assign an ownership lifecycle
event; aliasing it to membership removal would misrepresent an active member.

Preserve the prepared command for bounded retries and its safe `Recovery()`
binding across process loss. Recovery authenticates the same original actor
with a current genuine session and current organization membership/policy;
it must allow the successful former owner as a member without treating the
historical receipt as a new mutation grant. Callback withdrawal is rechecked
before disclosure. A fresh legitimate session may recover the same original
binding. Unknown never means retry under another command ID.

The existing membership schema and original command framing are retained;
no forward organization migration is necessary for these role/version updates.
Dynamic roles, federation, active organization/team selection and transport
integration remain outside this finite profile.
