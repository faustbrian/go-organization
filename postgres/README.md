# go-organization/postgres

Experimental native PostgreSQL composition for the root module's explicit-
organization membership profile. The existing identity Coordinator exclusively
owns transactions, command IDs, reservations, replay and scoped recovery.

## Composition and adoption

1. Apply the identity directory/credential/status, native session, authorization
   authority, protected risk/lockout, audit, outbox and lifecycle migrations.
   Add `MigrationSource` with an unused version to the same
   `go-migrations/v3.Runner` history. Audit owns its fixed cluster-role preflight.
2. Construct `NewRepository` from the migrated caller-owned primary pool.
3. Construct `NewContributor` with the native password profile, retained opaque
   session keys, policy identity/revision and finite limits.
4. Register it alongside kernel, audit, lifecycle outbox and native risk owners
   in the existing immutable `ContributorRegistry`. Construct the Coordinator
   with that registry and current command-query policy.
5. Construct `NewService` with those exact owners, real native SessionService,
   external authorization policy and matching root configuration. Risk must
   enforce native protected counters and current lockouts. No application
   organization store or UnitOfWork implementation is needed.

The canonical-ID callback validates the selected format; this adapter does not
invent a generator. Retain session keys while original sessions/pending commands
need them. All supplied pools/services are borrowed and must outlive calls.

## Public calls

Call `PrepareCreate(ctx, request, trustedCanonicalClientIP)`, persist its safe
`Recovery()` scope, then call `Execute(ctx, prepared)`. Preserve that exact value
for bounded retries. The client IP is transport-resolved, not a copied arbitrary
header. See the compiled example in `example_test.go`.

Inspect the receipt outcome. For `Unknown`, call
`Recover(ctx, currentAuthentication, retainedScope)` with a current genuine
session and policy. Recovery never rebuilds the command, re-delivers credentials
or renews original expiry. `Get` and `ListMembers` query current primary
membership on every call; no shared-cache closure is claimed.

Preparation can return preliminary root-policy errors such as `ErrLastOwner`.
Invariant denials discovered inside protected execution (quota or last-owner)
return the generic root `ErrForbidden` with `NotCommitted`; the native command
journal and audit retain a denial, not a dependency failure. The adapter uses
the Coordinator's supported typed denial rather than forwarding domain-only
sentinels that the Coordinator must sanitize. Terminal replay retains that
outcome and may return a nil error.

## Persistence and concurrency

The fixed `organization` schema stores organizations, membership tombstones,
cardinality counts and exact participant effect bindings. Effect bindings are
participant evidence, not a second journal. Domain and scoped authorization
changes share the existing Work transaction with audit and lifecycle outbox.

Native Work owns admission locks first. The participant then acquires a tenant
lock before organization/member rows. This coarse correctness boundary protects
counts and last-owner invariants; no callback or external network work runs
under it. Membership removal changes only that organization's subject authority,
never global user/credential epochs. Tombstone reactivation never resets versions.

## Verification and release

The `integration` suite requires `GOLIB_ORGANIZATION_TEST_POSTGRES_DSN` identifying
an isolated **task-owned cluster**, not a shared fixture: native audit roles are
cluster-wide. It creates/drops one exact database and audit roles. Real native
owners exercise rollback, contention and lost successful PostgreSQL COMMIT
responses. Those fast partition fixtures deliberately seed controlled identity
records; they are not genuine sign-in evidence.

`TestOrganizationGenuinePasswordConsumer` separately composes public
`go-identity/reference` owners on the same primary: two users take actual
signup, native queued verification delivery, capability confirmation and
password sign-in before their issued sessions drive organization
create/get/admit/list/remove and scoped denial. Only the bounded email sender
and outbound HIBP HTTP response are controlled provider seams. No user,
credential, authentication proof or session is inserted manually in that case.
Run it with `go test -tags integration -run TestOrganizationGenuinePasswordConsumer`.
This remains the finite single-factor password profile, not full platform
qualification or proof of unselected authentication/session profiles.

Root and adapter are independently releasable experimental modules. Public pins
must refer to published commits; permanent local replacements are unsupported.
See the [root API/exclusions](../README.md), [security](../docs/security.md) and
[release notes](CHANGELOG.md).
