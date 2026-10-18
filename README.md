# go-organization

> **Status: experimental.** Only the explicit-organization membership profile
> below is implemented. This is not a stable release or complete organization unit.

`go-organization` supplies storage-neutral organization policy and immutable
transaction handoff for organization creation and membership admission, listing
and removal with last-owner protection. The root API is an adapter prerequisite;
the native PostgreSQL implementation is delivered separately. The root alone
does not supply durable organization operations.

## API and selection

The native PostgreSQL service supplies durable operations. The root `Service`
owns real session authentication, external policy, validation and immutable
command preparation. Its `Repository` and exact `UnitOfWork.Execute`/`Recover`
contracts are adapter boundaries, not application workflow instructions.

- `PrepareCreate` selects a preallocated canonical ID and tenant-unique lowercase
  ASCII slug. The creator becomes an owner atomically.
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

## Non-goals

The root boundary does not own:

- enterprise single sign-on protocol behavior or SCIM wire behavior;
- billing or user interfaces;
- session persistence or application authorization policy; or
- database clients, migrations, transactions, caches, or background workers.

Invitations/delivery, teams, custom roles, ownership transfer, domain claims,
archive/delete commands, active selection, cache invalidation, SSO/SCIM and
HTTP/browser transport are unselected. Reserved database states are not public
operations. Their presence in planning material does not make them available.

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
completion. `modules.json` records the experimental root prerequisite.
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
