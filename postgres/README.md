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

`ListOrganizations(ctx, organization.ListOrganizationsRequest)` needs only the
current human's authentication, page limit and optional returned cursor. It
scans current active self-memberships using the existing tenant/user/organization
index, checks scoped authority and per-organization policy, then revalidates
after callbacks before disclosing metadata. No arbitrary subject, selection,
new schema, cursor-signing owner or application-written store is required.
See [listing semantics](../docs/list-organizations.md).

Preparation can return preliminary root-policy errors such as `ErrLastOwner`.
Invariant denials discovered inside protected execution (quota or last-owner)
return the generic root `ErrForbidden` with `NotCommitted`; the native command
journal and audit retain a denial, not a dependency failure. The adapter uses
the Coordinator's supported typed denial rather than forwarding domain-only
sentinels that the Coordinator must sanitize. Terminal replay retains that
outcome and may return a nil error.

## Persistence and concurrency

`PrepareLeaveMember(ctx, organization.LeaveRequest, trustedCanonicalClientIP)`
uses the same coordinator and tombstone mutation as removal with its distinct
self-only `identity.organization.member.leave` command/policy. It advances the
organization policy and membership-scoped authority, not global credentials or
sessions. The final owner cannot leave. No new migration is required.
Current membership remains mandatory for historical disclosure: after leaving,
`Recover` denies until legitimate readmission, and old team bindings stay invalid.
See [self-leave semantics](../docs/member-leave.md).

The selected [ownership-transfer profile](../docs/owner-transfer.md) uses
`PrepareOwnerTransfer` and the same `Execute`/`Recovery` boundary. Install the
password owner's selected action-proof migration and supply its native primary
source before enabling this operation. It requires an exact signed original
password proof for `identity.organization.owner-transfer`, at most 15 minutes
old, and fences the actual current session/credential and both memberships.
Both actor and target must have known-empty current MFA authority; bind their
exact MFA generations and fence them again before mutation and final commit.
An enrolled/unknown or changed factor generation denies despite a valid SFA
session. Use the MFA owner's actual authority migrations and initialized rows.
The source becomes `member`; the target becomes `owner`. Membership and scoped
authorization versions both advance, while member/owner counts are conserved.
There is no new organization migration or independent transaction owner.

`PrepareUpdate(ctx, organization.UpdateRequest, trustedCanonicalClientIP)`
uses the same `Execute`/`Recovery` path for bounded `Name`/`Slug` replacement.
It admits only current owners/administrators and fences the exact expected
organization version, original session, credential and current global/scoped
authorization. Tenant serialization protects slug uniqueness against both
create and update. Identical replacements return `ErrConflict` before execution;
stale versions and tenant-scoped slug collisions conflict without effects.
The existing migration already supplies these fields and uniqueness; no schema
upgrade or normalization change is introduced. Unmentioned future fields are
not cleared. Each successful update advances the organization/policy epoch by
one and atomically emits `organization.updated.v1` with protected audit action
`identity.organization.update`. Membership versions/counts and subject/global
authority remain unchanged. Names/slugs are absent from audit/outbox payloads.
Use authenticated `Get` for the current updated view, not historical recovery
as an authorization grant.

The fixed `organization` schema stores organizations, membership tombstones,
cardinality counts and exact participant effect bindings. Effect bindings are
participant evidence, not a second journal. Domain and scoped authorization
changes share the existing Work transaction with audit and lifecycle outbox.

Native Work owns admission locks first. The participant then acquires a tenant
lock before organization/member rows. This coarse correctness boundary protects
counts and last-owner invariants; no callback or external network work runs
under it. Membership removal changes only that organization's subject authority,
never global user/credential epochs. Tombstone reactivation never resets versions.

## Invitations

`InvitationMigrationSource` is a separate forward migration after the original
membership source. It preserves the installed migration bytes and stores only
safe recipient identifier/version, organization, member-only role, lifecycle,
expiry and delivery-effect fences. Revoking/removing an email identifier is not
blocked by an invitation foreign key; subsequent recipient admission fails.

`NewInvitationRepository` borrows the existing organization repository and real
initialized `delivery/postgres.EnqueueService`, with its exact retained policy
revision. The root `InvitationService` performs genuine session and action-policy
checks around this trusted port. Owner-only metadata additionally passes through
the delivery owner's current status authorization; an invitation ID alone grants
neither access nor evidence of a provider outcome.

Recipient preparation uses identity's bounded complete identifier partition and
`ResolveRecipient`, including current verified eligibility and independent
security epochs. Neither identity nor delivery SQL is copied. Listing closes
primary rows before delivery-owner calls; the1–100 bound also bounds per-item
status reads. One outer budget withholds an incomplete page rather than returning
partial metadata. This first profile makes no bulk-list throughput claim.

For native send/accept, also install `InvitationCapabilityMigrationSource` after
the invitation-read migration. It retains the original issuer envelope identity
and replay-key version privately, not the bearer or a second consumption ledger.
Existing invitation rows retain paired NULL values and cannot be accepted by
inferring custody from a presented proof.

Construct `NewInvitationService` with the same primary/session/policy owners,
actual shared issuer and preparation codec configuration, risk repository,
encrypted delivery contributor, renderer and status service. The issuer's
explicit maximum lifetime must cover the selected invitation lifetime (48 hours
by default); delivery dedupe must cover that lifetime plus 24 hours. Configure
`Delivery.PolicyVersion` and `ProviderVersion` from their retained delivery
profiles, and `StatusPolicyVersion` from `EnqueueConfig.PolicyVersion`, the
independent current status authorization revision. They are not interchangeable.

`PrepareSend` freezes an authorized genuine owner and the exact current verified
recipient. `Execute` repeats the current external action policy before native
reservation; prepared authority is not a cached policy allowance. It generates
custody only after the kernel acknowledges the
original protected preparation, then atomically persists the invitation, shared
one-use grant and encrypted delivery intent. Run the actual delivery owner's
worker separately; this service never calls the sender under a domain lock.
`PrepareAccept` binds the genuine recipient session and all original signed
organization/role/identifier/version/expiry scope. Its native execution consumes
that grant, creates or reactivates the actual member and organization-scoped
authority, and accepts the invitation in the same transaction. The primary
`invitation.accepted.v1` event is paired with a distinct `membership.created.v1`
event using the actual member versions. Existing membership is a conflict, not
an implicit successful accept. Get/List remain owner-only metadata operations;
neither projections nor recovery return bearer custody.

Persist `PreparedInvitation.Recovery()` before execution. After an unknown
outcome, pass that safe handle and current genuine authentication to `Recover`,
including on a new service instance. Historical metadata queries recheck the
current original actor and owning organization/recipient policy; they neither
require original execution expiry nor renew it. Send recovery reads the original
organization correlation from the sole kernel's frozen preparation declaration,
so acknowledged preparation can be observed and reconciled even before an
invitation row exists. Historical origin versions are not current authority;
current owner/action policy is checked separately. Legacy or missing durable
correlation fails closed rather than guessing that an unobserved send did not
commit. A caller-selected different organization cannot redirect reconciliation.

A definitive failed acceptance retains `NotCommitted` for its original command
and terminal-releases the unused grant under the shared capability owner's
contract. Zero uses does not make the proof reusable: a new command using it is
denied. Domain, scoped authority and lifecycle writes roll back, but the pending
invitation metadata remains until later lifecycle handling. An owner may send a
new independent invitation within the pending limit; this profile allows that
alongside an existing pending invitation. It does not silently reissue custody,
resend delivery, cancel the old invitation or reclaim its pending-limit slot.
Resend/reject/explicit-expire, recipient listing and other full-goal
profiles remain unimplemented.

### Pending invitation cancellation

Install the forward-only `InvitationCancellationMigrationSource` at a permanent
version after all already selected organization migrations before calling
`InvitationService.PrepareCancel`. Installed invitation migration bytes remain
unchanged; existing pending/accepted records and original issuer custody survive
the upgrade. `InvitationCancelRequest` selects exact organization and invitation
versions and current owner/administrator authentication. Recipient email removal
or suspension does not by itself block cancellation.

Execution uses the existing risk/coordinator/current-session, organization,
membership and scoped-authority owners. It atomically changes live pending1 to
cancelled2, persists the required standard-retention
`identity.organization.cancel_invitation` audit and `invitation.cancelled.v1`
outbox event, and records the original result. It neither sends another message
nor consumes/reissues a capability. An already queued/sent invitation may still
arrive, but its proof cannot authorize acceptance. Acceptance independently requires pending1;
accept/cancel contention has one terminal winner, and an unsuccessful acceptance
cannot retain provisional membership or capability consumption. No organization
policy epoch or global credential is changed because cancellation withdraws a
prospective grant, not existing membership authority. Cancelled rows cannot be
reused by this API; old readers encountering the new state fail closed.

Persist the existing safe `PreparedInvitation.Recovery()` handle before
execution. Cancellation recovery needs no original bearer/proof but does require
a current genuine session for the original actor and current owner/administrator
authority in the exact owning organization. Both external disclosure decisions
are followed by the existing native session/member/scoped-epoch fence; original
freshness is never renewed. Unknown results are reconciled through the sole
kernel, not replaced by a new cancellation command. Expired projections are not
live pending invitations and are not cancelled by this finite profile.
An original prepared cancellation retry that finds a retained result uses this
same current disclosure policy, while retaining its original freshness interval;
an old management membership cannot authorize replay of its historical receipt.

## Optional native teams

Install `TeamMigrationSource{Version: ...}` after the installed organization
migrations, then set identical positive `Core.Teams` and `ContributorConfig.Teams`.
Zero disables teams, including contributor operation advertisement; existing
membership/invitation migrations and command fingerprints are unchanged.
The forward migration preserves populated organizations/static memberships and
adds tenant/organization-scoped teams and version-bound membership tombstones.

The public `Service` provides create/add/remove preparation and team/member/mine
reads with the root request types. It uses the same `PreparedCommand`, `Execute`
and `Recover`, sole coordinator, protected audit and lifecycle outbox. Queries
use bytewise exclusive-ID cursors, 1..100 rows, over current primary state, not
retained snapshots. Ordinary members may inspect only their own team's members;
owners/admins may list all teams. Exact original session, current actor/target
membership and identity are fenced through the protected commit. Team changes
advance the shared organization epoch and the directly changed subject's scoped
authorization epoch, not global session authority or roles. An organization
remove/re-add does not restore any previous team binding: explicit re-admission
uses the new organization-member version and retained team-binding version.

The genuine password consumer continues through team create, compatible member
add, all three read surfaces and removal denial. Focused native tests additionally
cover quotas, duplicate contention, scope, authority withdrawal, rollback,
lost acknowledgement recovery and a populated forward migration. The optional
[team lifecycle profile](../docs/team-lifecycle.md) adds exact get, bounded name
update and terminal deletion after `TeamLifecycleMigrationSource` and explicit
`Teams.LifecycleVersion: 1`. Active selection, dynamic roles and HTTP composition
remain later profiles.

Recovery re-reads the submitted native session and the original current
organization/member role, policy and scoped-authority epochs after external
callbacks, including the kernel disclosure policy. A callback's allow cannot
preserve withdrawn authority or disclose a retained receipt. This shared check
also protects metadata-update recovery; another legitimate current session for
the same actor can still recover the exact original command binding.

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
create/get/update/admit/list/remove and scoped denial. Real owner and
administrator metadata updates preserve membership authority, while a genuine
member is denied. Only the bounded email sender
and outbound HIBP HTTP response are controlled provider seams. No user,
credential, authentication proof or session is inserted manually in that case.
The same case continues through actual invitation send, captured encrypted
delivery and recipient acceptance; it checks concurrency, exact paired lifecycle
events, wrong-scope denial, failed-accept terminal release, tombstone versions
and lost-COMMIT recovery through a new service and fresh password session.
Run it with `go test -tags integration -run TestOrganizationGenuinePasswordConsumer`.
This remains the finite single-factor password profile, not full platform
qualification or proof of unselected authentication/session profiles.

Root and adapter are independently releasable experimental modules. Public pins
must refer to published commits; permanent local replacements are unsupported.
See the [root API/exclusions](../README.md), [security](../docs/security.md) and
[release notes](CHANGELOG.md).
