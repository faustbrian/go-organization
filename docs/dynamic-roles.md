# Organization custom roles

This opt-in native profile uses explicit organization selection and genuine
password/bearer sessions. It is a finite M23 profile, not full organization or
identity-platform qualification. Team-derived permissions require the additional
explicit selection below. Active-role selection, conditions, wildcards, custom
management permissions and HTTP/reference composition are not selected.

## Selection and ceiling

Supply the same `DynamicRoleConfig` to core and PostgreSQL contributor:
`Version` identifies the deployed immutable policy, `MaximumRoles` is 1..100,
and `Catalog` contains 1..128 typed `Permission` entries. Each entry names one
exact action and resource type. All `identity.*` actions are excluded so custom
roles cannot expand management, ownership, recovery or identity authority.
The catalog is the deployment-approved application-permission ceiling available
to current static owners/administrators, not authority inferred from role names.
Construction copies catalog inputs. Policy/catalog changes require a new policy
configuration epoch and matching construction; original commands retain their
complete catalog fingerprint and cannot execute against a changed deployment.

Each role holds at most 64 typed statements and at most 8192 encoded bytes,
matching the existing identity command-field contract. Statements reference a
registered permission, an exact resource ID and `authorization.Allow` or `Deny`.
Empty roles intentionally grant nothing; unknown or malformed stored statements
deny the complete check rather than being ignored alongside a known allow.
Names are 1..256 UTF-8 bytes without controls or surrounding whitespace. Role IDs
must pass the selected canonical-ID validator and cannot equal a static role.

## Operations and precedence

Only current static owner/administrator members, independently allowed by the
configured organization action policy, may manage/read custom roles or bindings.
Custom role assignments never turn members into administrators or owners, and
the existing closed static roles and final-owner protection remain unchanged.

Create takes a new canonical role ID and exact organization epoch. Update fully
replaces name/statements at exact organization and role versions; it immediately
changes the permissions of existing bindings. Identical updates conflict.
Delete terminally retires the ID and denies every binding. Retained deleted IDs
count toward `MaximumRoles`; slots cannot be churned to grow tombstones without
bound. Listing is a current custom-role page with exclusive bytewise ID cursor
and 1..100 limit; static roles remain the closed `Role` constants, not custom
rows. No static-role resource statements are implied by that management status.

An exact `GetDynamicRole` may also select `TargetUserID`, under the same current
owner/admin `role.get` policy. It returns that scoped target membership and one
exact role binding: version zero for never assigned, or the current stored live
or revoked tombstone version. This lets a fresh client discover every mutation
precondition without retaining prior command results. List rejects the selector.
Membership `Active`/`Version` remains explicit and independent: a stored-active
assignment whose admission epoch no longer matches grants nothing. Foreign or
malformed target/binding metadata denies instead of fabricating a snapshot.

Assignment/revocation requires the exact organization, role, target member and
binding versions. A first binding uses zero; reassignment uses the retained
tombstone version. Bindings reference the member's exact organization admission
epoch, so removal/readmission or a static-role transition cannot revive them.
Deletion/update effects need no per-member fan-out. Independent organization
keys and unrelated member/session authority are not revoked by this profile.

`CheckPermission` accepts only the current authenticated member, exact requested
action/resource and required organization epoch. The external policy may veto
the check. The existing authorization RBAC evaluator and deny-overrides engine
evaluate current effective bindings: any matching explicit deny wins over allows;
no match denies. It returns the current organization epoch as `Decision.Revision`,
not a cached/session-derived lease. Cross-tenant/organization and removed-member
inputs deny. Epoch checks after role loading fence concurrent policy changes.

## Optional team-derived permissions

Set identical `DynamicRoles.TeamBindingsVersion: 1` on core and contributor,
with `Teams.LifecycleVersion: 1`. Install `TeamRoleBindingMigrationSource` after
both dynamic-role and terminal team-lifecycle migrations before activation.
Zero preserves direct-only configuration fingerprints and command framing.
Do not run old direct-only evaluators alongside the opted-in deployment: they
cannot evaluate team denies. Configuration changes require coordinated activation.

`GetDynamicRole` accepts an exclusive `TargetTeamID` instead of `TargetUserID`
to return the current team and exact absent/live/revoked binding. Current static
managers use those discovered organization, role, team and binding versions with
`PrepareAssignTeamDynamicRole` or `PrepareRevokeTeamDynamicRole`, followed by
ordinary `Execute`. These reuse the existing `role.assign`/`role.revoke` actions,
protected counters and original-command recovery; no new management authority
is inferred from the assigned role.

Effective evaluation includes each current role once across direct assignments
and all compatible current team memberships. An explicit deny on either path
wins over every allow. Team membership must match the user's current organization
admission epoch. Team removal, organization removal/readmission and terminal team
deletion deny old authority immediately, including on warm services. Legitimate
team re-admission requires an explicit membership change at current versions.
Deleting/updating a role affects both assignment paths without per-user fan-out.
Team bindings are bounded by retained team and role limits; binding changes
atomically advance both the shared team subject epoch and organization policy
epoch. They do not rewrite every member or confer ownership/static-management
rights. Terminal replay and original recovery retain current manager/session
checks. Active-team selection and HTTP/reference composition remain unselected.

## Persistence and recovery

Install `DynamicRoleMigrationSource` after `MigrationSource`, before selecting
the profile. No installed migration, static role or existing membership is
rewritten. Use the existing native Service and Coordinator; consumers supply
configuration and policy, not domain stores, transactions or retry journals.
All role/binding mutations advance the organization policy epoch atomically with
protected audit/lifecycle effects. Binding changes additionally advance existing
target organization-scoped authority without changing its static membership.

Retain the exact prepared command across bounded retries. For lost commit
acknowledgements use its safe `Recovery` handle and fresh current authentication
with the original command identity. Unknown remains unknown until the native
coordinator resolves it; recovery does not issue another assignment or permission.
Current owner/admin management authority is required even for historical disclosure.
Terminal `Execute` replay also performs these current checks; the original
unexpired observation does not disclose a committed receipt after manager/session
authority is withdrawn.
The migration does not enable HTTP routes or advertise unsupported capabilities.
