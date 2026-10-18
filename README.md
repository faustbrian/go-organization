# go-organization

> **Status: experimental.** Explicit-organization membership and the selected
> existing-recipient invitation profile below are implemented. This is not a
> stable release or complete organization unit.

`go-organization` supplies storage-neutral organization policy and a
[native PostgreSQL adapter](postgres/README.md). The selected profile creates
organizations, updates bounded names/slugs, admits existing active users,
lists members and removes members
while protecting the last owner.

## API and selection

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
- `PrepareRemoveMember` requires exact versions and retains a tombstone. Only
  owners remove owners; the final owner cannot be removed.
- `Execute` accepts the same immutable prepared command for bounded retries.
- `Get` and `ListMembers` require current active membership on every call.
  Listing uses exclusive UserID keysets and limits 1–100 over current committed
  state, not a retained snapshot. Earlier concurrent additions require restart.
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

Invitation resend/cancel/reject, recipient invitation listing, teams, custom
roles, ownership transfer, domain claims,
archive/delete commands, active selection, cache invalidation, SSO/SCIM and
HTTP/browser transport are unselected. Reserved database states are not public
operations. Their presence in planning material does not make them available.

## Selected invitation boundary

The storage-neutral `InvitationService` adds owner-send and intended-recipient
acceptance preparation to the same immutable `Command`/`UnitOfWork` contract.
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
Listing uses exclusive invitation-ID keysets with limits1–100. Recipient listing,
prospective-user signup, grants above member and all resend/cancel variants are
not selected by this profile.

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
`invitation.accepted.v1` (invitation1→2). Acceptance also requires the distinct
existing `membership.created.v1` transition for its actual membership version;
an invitation event must not masquerade as that membership event. Exact audit
actions are `identity.organization.create_invitation` and
`identity.organization.accept_invitation`.

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

## License

MIT. See [LICENSE](LICENSE).

## Documentation navigation

[Complete documentation map](docs/README.md#complete-documentation-map)

Use the [versioned ecosystem entry](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md) for package
selection. The [frozen compatibility cohort](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/compatibility-sets.md)
is separate from current package releases and unpublished source changes.
Adopting them does not silently update that cohort.
