# go-organization

## Transport-neutral direct-operation requests

`CreateOperationRequest`, `UpdateOperationRequest` and
`AddMemberOperationRequest` carry one required
`identity.IdempotencyKey`; `RemoveMemberOperationRequest` is a non-keyed,
exact-version repeat operation. The durable operation owner allocates command
IDs and create IDs, retains original request correlation, and distinguishes
not-committed, committed and unknown outcomes. A retained request key or absent
membership never establishes a committed domain mutation. Matching retries
must not allocate another command or renew original authority.

`OperationRecoveryRequest` carries an original safe binding plus current
authentication; it grants no permission to resubmit or disclose the operation.
Every request's `Validate` checks syntax and custody presence only, without IO
or authentication. These direct request types reject implicit JSON/text export;
HTTP integrations own separate bounded wire schemas and credential acquisition.
Metadata replacement retains `UpdateRequest`'s bounded name/slug and exact
expected organization version. A matching Update key recovers only its original
command; changed metadata, organization or version conflicts, and an unknown
outcome grants no permission to execute again. Current authority is still
required to disclose its original outcome.
Existing `CreateRequest`, `UpdateRequest`, `MemberRequest` and `Prepare*` APIs
are unchanged.
These additive contracts alone do not enable a durable operation or HTTP route.

`InvitationSendOperationRequest` selects one existing verified recipient by user
and identifier ID, the exact organization/version, and one required initiating
key. The durable native owner allocates command and invitation IDs and retains
the original member role, deadline and delivery policy. Matching retries recover
only that original outcome; an unknown outcome cannot authorize another send.
There is no submitted address, caller role or proof in this request. Existing
explicit `InvitationSendRequest` and native acceptance contracts are unchanged.

> **Status: experimental.** Explicit-organization membership and the selected
> existing-recipient invitation, opt-in team-membership and domain-reservation
> profiles are implemented. This is not a
> stable release or complete organization unit.

`go-organization` supplies storage-neutral organization policy and a
[native PostgreSQL adapter](postgres/README.md). The selected profile creates
organizations, updates bounded names/slugs, admits existing active users,
updates static membership roles, lists members and removes members
while protecting the last owner.

## API and selection

`LifecycleConfig` selects [native owner archive/restore](docs/lifecycle.md).
Current owners supply a fresh action-bound password proof and exact discovered
organization version. Archive denies native child authority and cancels pending
invitations atomically; restore never revives terminal child state. Hard deletion
and complete asynchronous external cascades remain unselected.

`DynamicRoleConfig` selects [bounded custom roles](docs/dynamic-roles.md).
Current owners/administrators create/read/list/update/delete roles and assign or
revoke them for current members. `CheckPermission` evaluates exact registered
action/resource statements through the existing authorization RBAC engine, with
explicit deny precedence and a required current organization policy version.
Custom roles confer no organization-management or ownership authority. Zero
configuration disables this profile. `TeamBindingsVersion: 1` additionally selects
team bindings with terminal team lifecycle and its forward migration; zero keeps
the existing direct-only profile.

`GetDynamicRole` optionally accepts `TargetUserID` to return that exact member's
current membership and absent/live/tombstone role binding. Fresh managers can
discover the versions needed to revoke or reassign without application history;
`ListDynamicRoles` does not accept a target selector. The team profile instead
accepts exclusive `TargetTeamID` for exact team/binding versions, then
`PrepareAssignTeamDynamicRole` or `PrepareRevokeTeamDynamicRole`.

`DomainConfig` selects authenticated [domain reservation custody](docs/domain-claims.md):
current owners/administrators prepare a reservation, read their organization's
current claim, and withdraw its exact version. Zero leaves this profile disabled.
Reservations are globally exclusive in the native PostgreSQL adapter but are
never proof of domain ownership and never enable SSO routing.

`InvitationService.PrepareResend` selects a current owner/administrator and the
exact pending invitation and organization versions. It preserves the original
recipient, verified identifier, member role and exclusive deadline; it does not
accept a replacement address or a renewed lifetime. Preparation alone issues
no proof. Durable supersession requires the native capability/delivery owners
and one atomic commit, so the predecessor and successor are never independently
consumable. Retain the original command for retries and recovery.

`Invitation.IssuedVersion` identifies the pending proof generation. A pending
or naturally expired projection has `Version == IssuedVersion`; a durable
terminal transition has `Version == IssuedVersion + 1`. For source compatibility,
zero `IssuedVersion` means the original issued version1. Resend requires room
for both the successor version and its later terminal transition.

`InvitationService.PrepareExpire` selects the current owner/administrator and an
exact pending invitation/version with a reason from configured
`InvitationConfig.ExpirationReasons`. An empty registry leaves expiry disabled.
Explicit expiry can precede the natural deadline or terminalize an elapsed
pending row: `InvitationExpired` at its issued version is only a natural projection;
the next version is a durable terminal effect that prevents every prior proof from
authorizing acceptance. See the adapter's
[schema and recovery requirements](postgres/README.md#explicit-invitation-expiry).

`InvitationService.PrepareReject` admits only the authenticated intended verified
recipient of an exact pending invitation, using original organization/invitation
versions without membership or an invitation proof. The native adapter atomically
stores the next terminal version with canonical audit/event effects; the original
capability can no longer authorize acceptance. See the adapter's
[migration and recovery requirements](postgres/README.md#recipient-invitation-rejection).

Use the native `postgres.Service` for durable operations. The root `Service`
owns real session authentication, external policy, validation and immutable
command preparation. Its `Repository` and exact `UnitOfWork.Execute`/`Recover`
contracts are adapter boundaries, not application workflow instructions.

- `PrepareCreate` selects a preallocated canonical ID and tenant-unique lowercase
  ASCII slug. The creator becomes an owner atomically.
- `PrepareUpdate` replaces only `Name` (1–256 UTF-8 bytes, no ASCII control
  characters or surrounding whitespace) and `Slug` (1–63 lowercase ASCII letters/digits/
  hyphens, no leading/trailing hyphen), preserving exact spelling. It requires
  a current owner or administrator and the expected organization version.
  Identical values return `ErrConflict` without a transition. Slug collisions
  conflict within the same tenant, including reserved lifecycle states.
- `PrepareAddMember` requires an existing active target user, static role and
  expected organization/member versions. Administrators cannot add owners.
- `PrepareUpdateMember` changes an exact active membership's static role with
  expected organization/member versions. Only owners may grant or demote owners;
  the final recovery-capable owner cannot be demoted. See
  [static role updates](docs/member-role-update.md) for authority and recovery.
- `PrepareRemoveMember` requires exact versions and retains a tombstone. Only
  owners remove owners; the final owner cannot be removed.
- `PrepareLeaveMember` accepts an explicit organization/version and derives self
  from the current session, including ordinary members. It cannot select another
  target or remove the final recovery-capable owner. See [self leave](docs/member-leave.md).
- `PrepareOwnerTransfer` selects an existing active nonowner member and exact
  organization/source/target versions. A current owner and operation-bound
  primary proof are required; the former owner becomes an ordinary member.
  See [ownership transfer](docs/owner-transfer.md) for authority and recovery.
- `Execute` accepts the same immutable prepared command for bounded retries.
- `Get` and `ListMembers` require current active membership on every call.
  Listing uses exclusive UserID keysets and limits 1–100 over current committed
  state, not a retained snapshot. Earlier concurrent additions require restart.
- `ListOrganizations` lists only the authenticated human's active organizations
  with 1–200 results, per-organization policy and stable visible-ID pagination.
  Its additive repository capability leaves existing implementations compatible.
  See [organization listing](docs/list-organizations.md) for filtering and bounds.
- `Recover` authenticates the current actor against exact original scope. An ID
  alone grants no result access; recovery never re-executes a command.

Membership removal advances scoped organization authorization, not unrelated
global user or credential authority. Re-admission advances the retained
membership and scoped authority rather than resetting them.
Metadata updates advance only the existing organization/policy epoch; they do
not change memberships, scoped subject authority or global identity authority.
Read the updated organization through authenticated `Get` after the receipt.

The selected update profile maps the planning operation
`identity.organization.update` onto the existing `Authentication`, stable
`CommandID`, `OrganizationVersion`, and `PrepareUpdate`/`Execute`/`Get` model.
It retains the committed canonical-ID policy and create-name 256-byte bound,
not older generated catalog assumptions of 22-character IDs and 128-byte names.
Optional typed additional fields and the one-call/HTTP `UpdateResult` surface
are unselected; they are never silently cleared or emulated.

## Non-goals

The root boundary does not own:

- enterprise single sign-on protocol behavior or SCIM wire behavior;
- billing or user interfaces;
- session persistence or application authorization policy; or
- database clients, migrations, transactions, caches, or background workers.

Domain challenges and ownership proofs,
hard-delete commands, active selection, cache invalidation, SSO/SCIM and
HTTP/browser transport are unselected. Reserved database states are not public
operations. Their presence in planning material does not make them available.

## Selected invitation boundary

The storage-neutral `InvitationService` adds owner-send, intended-recipient
acceptance/rejection and owner/administrator resend/cancellation/expiry
preparation to the same immutable
`Command`/`UnitOfWork` contract.
This root boundary alone is not durable invitation issuance or consumption;
the native `postgres.NewInvitationService` supplies the sole coordinator,
capability and delivery owners from actual public configuration. Applications
do not implement a token store or transaction coordinator.

Send selects an existing active user and exact verified email identifier. It
freezes the organization, recipient, identifier/version, member-only role and
exclusive expiry; it never accepts a caller-selected address or privileged role.
Acceptance requires independent genuine session authentication and an exact
one-use, non-bearer capability for that recipient, invitation and organization.
Existing active membership conflicts without overwriting its role or consuming
the capability. Current recipient, policy, expiry and membership must be fenced
again by native execution, atomically with shared capability consumption.

`Get`/`List` expose only current owner-authorized scalar metadata and the existing
delivery owner's state/effect ID. They expose no transport address, proof or
encrypted custody. Provider `Accepted` is not confirmed `Delivered`. Pending
records project as expired at the exclusive deadline without a new mutation.
Listing uses exclusive invitation-ID keysets with limits1–100.
Prospective-user signup and grants above member are not selected by this profile.

Configuration explicitly selects a lifetime within15 minutes–30 days and a
pending bound within1–10000; the reference selection is48 hours/100. A48-hour
composition must explicitly enlarge capability lifetime limits and delivery
deduplication retention to at least lifetime+24 hours. No default capability
policy is silently weakened. Neither verification nor metadata is permission
to consume, and unknown command outcomes retain the original invitation ID.

Native send/accept and new-service metadata recovery are exercised by the
[genuine public consumer](postgres/invitation_consumer_integration_test.go).
A definitive failed acceptance terminal-releases its unused grant: it is not
reusable under a new command. A new owner-authorized send can issue a distinct
grant within the pending limit; it does not silently resend or cancel the old
pending row. Preserve the safe recovery handle before executing and reconcile
ambiguous outcomes before selecting any new command.

The owning lifecycle catalog adds `invitation.created.v1` (invitation0→1) and
`invitation.accepted.v1` (issued invitation version→next terminal version).
Acceptance also requires the distinct
existing `membership.created.v1` transition for its actual membership version;
an invitation event must not masquerade as that membership event. Exact audit
actions are `identity.organization.create_invitation` and
`identity.organization.accept_invitation`.

`PrepareCancel(InvitationCancelRequest)` selects the exact live pending
invitation and expected organization/invitation versions. It authenticates a
current owner or administrator, not the recipient, and needs no invitation
proof or current recipient email. The distinct callable operation is
`identity.organization.invitation.cancel`; its canonical audit action is
`identity.organization.cancel_invitation` (standard retention), paired with
`invitation.cancelled.v1` (invitation1→2). Existing send/accept retention is
unchanged. Cancellation grants no membership and changes no organization or
global identity authority. Cancelled IDs remain terminal: a still
cryptographically valid predecessor proof, including an already-prepared
acceptance, cannot pass the shared pending/version fence. Retries preserve the
original command; metadata recovery requires current management authority.

`ListMine(InvitationListMineRequest)` is a distinct current-recipient read,
without organization membership or administrator permission. It returns only
safe `Invitation` values bound to the authenticated human and an exact current
verified email identifier ID/version. Every supported lifecycle state is
visible; pending records project expired at their exclusive deadline. Old
identifier versions, removed or unverified identifiers are not historical access
grants. No delivery status, address, capability or ciphertext is returned.

The optional `InvitationListMineReader` preserves existing repository callers.
Pages use limits1–200 and a scope-bound opaque continuation, with tenant-unique
invitation IDs in C byte order. This is a current keyset, not a snapshot: earlier
inserts require restarting. No page escapes on late identity/session/policy or
invitation withdrawal; original session freshness is never renewed. Retained
invitation metadata itself grants neither membership nor acceptance authority.

## Lifecycle and ownership

Supply a real native stateful opaque bearer session with verified single-factor
password authentication. Organization-, factor- and passkey-bound sessions are
rejected, not downgraded. Supply external policy, canonical-ID validation,
positive operation budgets of at most five seconds, and finite
member/per-user/per-tenant limits. Native budgets must fit the enclosing budget.

The caller owns primary pools, transport, retained keys and shutdown. Mutable
key maps are copied; no package background work or authorization cache starts.
Do not log names or bearer-bearing preparations. Commands and authentication
reject automatic serialization; persist only safe recovery scope.

## Outcomes and retries

Inspect `StoreResult.Receipt.Outcome`, not error presence alone. Terminal
`NotCommitted` replay may return a nil error. `Unknown` means the server may
have committed: reconcile through scoped recovery, never a new command ID.
Preparing again captures new observations and is not an idempotent replay.
Retries and recovery never renew original session expiry.

## FAQ and tradeoffs

**Why explicit IDs?** Active-session organization selection is a later profile;
current membership and policy are checked for the supplied ID.

**Why a tenant lock?** The native adapter serializes tenant mutations to protect
cardinality and last-owner invariants. This profile makes no throughput claim.

## Planning and verification

The [repository goal](docs/goal.md) describes the full later unit, not current
completion. `modules.json` records the experimental root and optional adapter.
Full platform composition and release qualification remain pending.

See the [security boundary](docs/security.md), [release notes](CHANGELOG.md), and
[SECURITY.md](SECURITY.md) for private reporting; no stable release is supported.

Use Go 1.27.2 and the qualified public Tools v2.1.2 binary; the planned
module minimum remains Go 1.27.0. `make check`, `make ci` and `make fast-check`
validate configuration, repository structure, cohesion, offline specification
decisions, local documentation links and whole-tree/history secrets.
CI uses the same structural commands plus validated PR-base or push-before
changed-content secret checks on every change. Ordinary Required has a
five-minute job limit; changed secrets have a forty-second fatal timeout.
Scheduled/manual runs retain whole-tree secrets and online authority refresh.
`make check-full` explicitly preserves the previous full/online contract.
These commands do not run application tests or establish runtime/release proof.
See [contributing](CONTRIBUTING.md) for public tooling installation and scope.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## Optional team-membership profile

Set the same explicit `TeamConfig{Version: 1, MaximumTeams: 100,
MaximumMembers: 100}` on core and native contributor configuration, and install
the adapter's forward `TeamMigrationSource` after existing organization
migrations. Zero configuration disables the entire profile and registers no
team mutations. Limits are bounded startup policy, not implied protocol defaults.
`MaximumMembers` caps currently compatible active bindings, not lifetime retained
removal tombstones; operators retain responsibility for storage/retention sizing.

Owners and administrators call `PrepareCreateTeam`, `PrepareAddTeamMember` or
`PrepareRemoveTeamMember`, then the adapter's ordinary `Execute`; preserve its
prepared command/recovery binding for replay or ambiguous commits. Requests bind
the exact organization policy, team, organization-member and team-membership
versions. Use `ListTeams` for management, `ListMyTeams` for the authenticated
subject, and `ListTeamMembers` for managers or current members of that team.
Reads are bounded exclusive-ID pages and revalidate native current session,
organization membership and scoped authority after action policy.

Each team mutation advances the organization policy epoch. Membership changes
also advance that subject's existing organization-scoped authorization epoch,
without changing roles, granting permissions or global session authority.
Organization removal immediately makes old team bindings unusable; re-admission
requires an explicit team add against the new organization-member version and
retained team tombstone version. The additional [team lifecycle profile](docs/team-lifecycle.md)
selects exact get, versioned name update and terminal delete only after its
forward migration and explicit `LifecycleVersion: 1`. Direct custom roles are
selected separately by `DynamicRoleConfig`; its optional `TeamBindingsVersion: 1`
adds effective team permissions. Active team selection, HTTP/reference
registration and full M23 remain unselected.

## License

MIT. See [LICENSE](LICENSE).

## Documentation navigation

[Complete documentation map](docs/README.md#complete-documentation-map)

Use the [versioned ecosystem entry](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md) for package
selection. The [frozen compatibility cohort](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/compatibility-sets.md)
is separate from current package releases and unpublished source changes.
Adopting them does not silently update that cohort.
