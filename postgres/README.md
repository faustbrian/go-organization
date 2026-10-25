# go-organization/postgres

Experimental native PostgreSQL composition for the root module's explicit-
organization membership profile. The existing identity Coordinator exclusively
owns transactions, command IDs, reservations, replay and scoped recovery.

## Optional original-key invitation send

`NewInvitationOperationService` borrows an existing genuine native
`InvitationService`. Its `Send(ctx, organization.InvitationSendOperationRequest,
trustedCanonicalClientIP)` allocates command/invitation IDs through the existing
immutable request-key owner and then uses the existing invitation engine. The
request selects an exact organization/version and existing verified recipient
user/identifier, never an address or caller role. Member role, original expiry
and delivery configuration are frozen. Existing explicit `PrepareSend` and
one-use `PrepareAccept` APIs remain unchanged; this adds no HTTP route.

Supply `InvitationOperationServiceConfig` with an explicit current request-key
policy admitting `identity.organization.invitation-send` on the exact
`identity.request-admission` route/resource, a fixed namespace/lookup key,
`ConfigurationID`, closed `OperationCustodyConfig` and bounded concurrency-safe
canonical `NewInvitationID`. The source's native query/admission, owner, session,
verified recipient and protected-risk policies still apply independently. Change
the configuration identity for material changes to borrowed policy, signing,
verification or canonical-ID collaborators; retain the original profile and all
referenced envelope/fingerprint/request keys for recovery. Scalar send settings,
including expiry, recipient/version and delivery policy, are also authenticated
and bound to initiating intent. Correlation changes do not rewrite the original.

Install the kernel's `RequestKeyMigrationSource`,
`RequestKeyPreparationMigrationSource` and later optional
`RequestKeyExpiryMigrationSource` before selecting this facade, preserving the
installed history/checksums and using an unused successor version. The expiry
upgrade alters the existing global command-ID claim and installs irreversible
fence triggers; it is not a second outcome store. Its table lock/check validation
can scan existing claims: use the migration owner's bounded deployment window
and roll forward on failure. Do not enable the API before that migration. The
native invitation/capability/delivery and other selected owner migrations remain
required as described below.

Only the invocation retaining the acknowledged winning mapping and its genuine
private original session preparation can execute. Concurrent missing-key callers
may prepare discarded code-free candidates; they cannot charge risk, sign, queue
delivery or mutate domain state during mapping. Authenticated encrypted custody
retains complete original native feature fields, verified recipient and the
earliest original session/invitation deadline, but no raw bearer, client key or
invitation proof. Input plaintext is bounded to64KiB and never truncated. Matching
keys/restarts only recover original metadata, under current genuine session,
owner/membership and exact verified-recipient checks before and after disclosure
callbacks. They never rebuild preparation, renew expiry or redeliver proof.

Inspect `Receipt.Outcome`, including when an error is returned. A committed or
aborted journal remains under the existing sole recovery owner. An original
mapping with no claim remains **Unknown** before its immutable deadline. After
primary-database expiry, the kernel may atomically install its exact irreversible
global-ID refusal and return metadata-only **NotCommitted**. A competing existing
claim is never retired or relabeled. Lost COMMIT acknowledgement remains Unknown
until exact reconciliation. Neither outcome permits that ID/key to execute again;
no automatic replacement key is allocated. Ordinary public `InvitationService`
recovery still requires its genuine journal origin and cannot disclose this
mapping-only refusal. This exception does not change other operation profiles'
mapping-only Unknown contract.

## Optional direct organization operations

`NewOperationService` borrows an existing genuine native `Service`; it directly
implements transport-neutral `CreateOperationRequest`, `UpdateOperationRequest`,
`AddMemberOperationRequest`, `RemoveMemberOperationRequest`, `ReadRequest` and
`OperationRecoveryRequest` signatures. No application store, coordinator,
`UnitOfWork` adapter or HTTP dependency is needed. Existing `Prepare*` APIs are
unchanged. The facade selects only create/update/get/member-list/add/remove, not
invitations, teams, browser cookies or active organization selection.

Before selecting it, install the identity coordinator's
`RequestKeyMigrationSource` and `RequestKeyPreparationMigrationSource` and the
later `OperationLookupMigrationSource`. Allocate an unused later organization
migration version, append it to the **same installed runner namespace/history**
and use `go-migrations/v3.Runner`. The removal index uses
`TransactionModeNone` with `CREATE UNIQUE INDEX CONCURRENTLY`; wrapping it in
an application transaction is invalid. The additive partial index covers only
committed removal history `(tenant_id, organization_id, before_version)`.
Existing aggregate epoch serialization guarantees that uniqueness. Existing
writer schemas and migration checksums do not change; unrelated effects add no
index entries. A failed/interrupted concurrent build requires inspecting and
reconciling the exact invalid index before retrying the migration; there is no
destructive automatic rollback or table rewrite.

Supply current matching coordinator query/admission and request-key policies,
immutable request namespace/lookup key, retained fingerprint keys, a fixed
`ConfigurationID`, closed `OperationCustodyConfig`, and a bounded concurrent-safe
canonical organization-ID callback. Change the configuration identity when the
selected policy/configuration materially changes; old input must not silently
enroll in a new profile. Retain envelope, request-lookup and fingerprint keys for
as long as original mappings need recovery. All dependencies remain borrowed;
the facade starts no goroutines and owns no pool shutdown.
This selected profile uses native default audit limits and the lifecycle
owner's fixed default schema; private custom limits hidden in a source registry
are not inherited. Its per-invocation registry binds the exact isolated native
participant rather than an application callback or wrapper identity.

Create/update/add each require the **single original client key**. The existing kernel
atomically admits its scoped mapping and native encrypted safe original binding.
Only the live winning preparation may proceed through actual native protected
risk admission and execution. Concurrent candidates may allocate discarded IDs;
matching retries/restarts never allocate again, reconstruct bearer authority,
renew deadlines or execute a new command. Ciphertext retains no raw bearer,
client key or submitted body. Current recovery uses the real session,
membership, authorization and journal owners again.

`Update(ctx, UpdateOperationRequest, trustedCanonicalClientIP)` replaces only
the bounded name/slug at the exact expected organization version. Select
`identity.organization.update` in the actual request-admission/query policy;
native current owner/administrator, action, session, scoped authority and
privileged risk checks still apply independently. No additional migration is
needed for Update. A successful transition advances the organization epoch
once, not membership or global authority. Stale versions, identical replacements
and tenant slug conflicts retain the existing metadata owner's conflict rules.
The intent binds organization, version, name, slug and configuration. Changing
any of them under the same original key conflicts; changing only correlation
does not rewrite the original command. Matching retry and `RecoverOperation`
recheck current disclosure authority without preparing against newer metadata,
renewing authority or converting a mapping-only unknown result into execution.
This additive native method does not enable an HTTP route.

Remove is **not keyed**. Pass exact expected organization/member versions and
no client command ID. A repeat probes the owned removal effect for the same
actor/target/epoch, checks the native tombstone, discovers the actual original
kernel binding and recovers its real receipt under current authority. An absent
member, fabricated receipt, different actor or later re-admission cannot provide
success. Native last-owner protection remains mandatory.

Inspect `Receipt.Outcome` even when the returned error is nonnil. An unknown
outcome retains original correlation and must not be resubmitted. A definitive
rollback keeps its original `NotCommitted` failure after a dependency recovers.
Safe binding metadata is correlation only, never a disclosure or mutation
capability. The exact registered native decoder authenticates its retained
mapping for the kernel's explicit `RecoverPreparedFeatureCommand` path. A real
mapping with no journal/claim remains **Unknown** with original correlation:
the original invocation could still create its journal, so absence is never
`NotCommitted` or a fresh execution grant. Ordinary generic recovery retains
its uniform absent/denied privacy. Missing/foreign/corrupt mappings disclose no
new receipt; recovery never reconstructs authority or executes the command.

The transport must supply the trusted canonical full client address and enforce
its selected HTTP rate policy. Native protected risk limits are separate and
remain inside the existing durable owner.

## Optional native archive/restore

See the [lifecycle contract](../docs/lifecycle.md). Install
`LifecycleMigrationSource` after all installed organization migrations (including
the complete invitation-resend chain when selected), then supply identical
`LifecycleConfig` and real matching `ArchivePrimary`/`RestorePrimary` sources.
`GetLifecycle` provides owner-only current active/archived version discovery;
`PrepareArchive`/`PrepareRestore` use ordinary `Execute` and original recovery.
Current owner, session, signed action proof and actual MFA authority are fenced
through commit. Local archive cancellation, policy state and protected effects
are atomic; no external cascade completion or hard deletion is claimed.

## Direct custom roles

Install `DynamicRoleMigrationSource` after the base organization migration, then
select identical nonzero `DynamicRoles` in core and contributor configuration.
See [the public role/permission contract](../docs/dynamic-roles.md) for the
finite catalog, exact-resource statements and version fences. Optional team
inheritance requires `TeamRoleBindingMigrationSource` after dynamic roles and
terminal team lifecycle, then identical `DynamicRoles.TeamBindingsVersion: 1`
and `Teams.LifecycleVersion: 1` on core/contributor. Do not mix direct-only
evaluators with the opted-in deployment: they cannot enforce team denies.
The risk supplier must classify `identity.organization.role.assign`
and `.revoke` as privileged; missing classifications fail closed, not bypass
protected counters. Existing role create/update/delete classifications also apply.

Use `PrepareCreateDynamicRole`, `PrepareUpdateDynamicRole`,
`PrepareDeleteDynamicRole`, `PrepareAssignDynamicRole` or
`PrepareRevokeDynamicRole`, then `Execute` the returned exact preparation.
`GetDynamicRole`, `ListDynamicRoles` and `CheckPermission` perform current primary
reads without positive caches. Deletion retires the role and all effective
bindings without per-member fan-out; no reassignment is selected. Role identity
tombstones count toward the configured per-organization limit.

For a fresh client, `GetDynamicRole` with `TargetUserID` supplies the exact target
membership and absent/live/tombstone binding versions needed by revoke or assign.
The returned stored `RoleBinding.Active` flag is not permission: target membership
must still be active at the recorded admission version. A terminal `Execute`
replay applies the same current manager/session checks as explicit `Recover`.

The existing coordinator commits each role/binding change, organization policy
epoch, protected audit and lifecycle event atomically. Binding changes also
advance the target's existing organization-scoped authorization authority.
`Recovery`/`Recover` retain the original outcome, never replay a grant, and
require the original actor's current owner/administrator authority and session.

## Domain reservation custody

Apply `DomainClaimMigrationSource` after `MigrationSource`, then select identical
nonzero `Domains` in core and contributor configuration. Its `MaximumClaims`
bounds all retained claims per organization, including withdrawal tombstones.
The risk supplier must classify `identity.organization.domain.reserve` and
`identity.organization.domain.withdraw` as privileged mutations; an older
supplier denies those operations rather than silently bypassing counters.

`PrepareReserveDomain`, `GetDomainClaim` and `PrepareWithdrawDomain` provide the
[reservation-only public profile](../docs/domain-claims.md). PostgreSQL's global
partial unique index arbitrates requested canonical domains across tenants.
The same coordinator commits claim custody, organization epoch, participant
binding, protected audit and lifecycle outbox together. Replay and `Recover`
use the original command identity; reconstruction needs only the safe `Recovery`
metadata and fresh current owner/administrator authentication. Neither a
reservation nor a historical committed receipt is domain ownership evidence.

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

`PrepareUpdateMember(ctx, organization.MemberRequest, trustedCanonicalClientIP)`
changes one exact active membership's static role. Current owners/administrators
can manage nonowners; only owners may grant or demote owners. The last owner
(this profile's recovery administrator) cannot be demoted. Membership and scoped
subject authority each advance once, and the organization policy epoch advances
once; counts and required protected audit/lifecycle commit in the same existing
Coordinator transaction. No new migration is required. Current reads and native
management operations use the new static role. Optional direct custom roles
are selected separately and do not confer static management authority.
Preserve the original prepared command and safe recovery binding. Exact
self-demotion history follows current membership/action/query admission, not
renewed manager privilege; other-target history retains current owner/admin
admission. See [static role updates](../docs/member-role-update.md).

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

Legacy send and acceptance recovery re-read the submitted session after all
disclosure-policy callbacks. Send also fences the exact current organization,
owner membership and scoped authority; acceptance re-reads the organization,
verified recipient, invitation and any existing target membership. A withdrawal
during either callback returns no historical projection. This does not require
membership for an intended recipient whose acceptance rolled back, change the
original outcome or expiry, renew execution authority, or regenerate delivery.

A definitive failed acceptance retains `NotCommitted` for its original command
and terminal-releases the unused grant under the shared capability owner's
contract. Zero uses does not make the proof reusable: a new command using it is
denied. Domain, scoped authority and lifecycle writes roll back, but the pending
invitation metadata remains until later lifecycle handling. An owner may send a
new independent invitation within the pending limit; this profile allows that
alongside an existing pending invitation. It does not silently reissue custody,
resend delivery, cancel the old invitation or reclaim its pending-limit slot.
Other full-goal profiles remain unimplemented.

### Invitation resend and supersession

Install `InvitationResendMigrationSource` at an unused permanent version after
the expiry migration, before selecting resend. Previous migration bytes and
version1/2 rows remain unchanged. The forward schema retains an issued version
and the original resend command's delivery effect on the existing domain effect
record. Pending `Version == IssuedVersion`; a durable terminal transition is
one version later. Natural expiry still projects the pending issued version
without writing. Older binaries fail closed on later pending versions; do not
use them to accept a resent invitation.

`PrepareResend` requires a current genuine owner/administrator, exact pending
invitation and organization versions, and the original current verified email
recipient. It accepts no role/address override. Preparation issues nothing.
The existing kernel acknowledges original preparation before the real issuer
generates one successor and transfers its proof into encrypted delivery custody.
One commit replaces this same invitation's proof/version and delivery effect,
with `invitation.resent.v1`, canonical standard-retention
`identity.organization.resend_invitation` audit and original command effects.
Recipient, identifier/version, member role, creator and original exclusive
deadline are unchanged. No membership or organization authority epoch advances.
The predecessor cannot accept after that commit, including a prepared acceptance
or a new service holding the original proof. A failed transaction preserves the
predecessor and rolls back successor, delivery, audit and lifecycle effects.

Use `ExecuteResend` for a typed `InvitationResendResult`; generic `Execute`
keeps the core receipt/IDs contract unchanged. A non-nil `Delivery` observes
only this original command's effect ID and delivery-owned state, never a proof,
address or the invitation's latest delivery. Provider acceptance is not confirmed
receipt. Administrators can use this result without widening owner-only
`Get`/`List`. An unknown or failed outcome has no invented delivery state. If
commit is known but the later authorized status read fails, the result retains
that committed receipt and returns an error with `Delivery == nil`.

Retain the same prepared command for retries and persist its safe `Recovery()`
handle before execution. Use `RecoverResend` with current genuine authentication
for code-free history, including after process reconstruction, later resends or
acceptance. Current manager/session/scoped authority, action and recovery policy
remain mandatory; the existing metadata owner applies its own delivery policy.
Historical results describe the original transition and original delivery, not
fresh issuance. Neither retry nor recovery signs again, renews the deadline,
redelivers or creates a new journal.

### Explicit invitation expiry

Install `InvitationExpiryMigrationSource` at an unused permanent version after
the rejection migration. It preserves installed migration bytes, existing
rows/custody and original natural deadlines. Earlier readers fail closed on
the new stored terminal state. Select bounded, unique registered non-secret
codes in `InvitationConfig.ExpirationReasons`; empty configuration keeps expiry
disabled. The risk owner must supply the canonical privileged expiry profile:
an unsupported or default-deny classification is not bypassed by this adapter.

`PrepareExpire` requires a current genuine owner/administrator, exact
organization/invitation versions and a registered reason. Recipient credentials
and invitation proofs confer no administrative authority. Explicit expiry may
close a live invitation early or terminalize a still-pending elapsed row. Safe
metadata uses `InvitationExpired` at issued version+1 for the committed terminal
state; the natural-deadline projection retains the issued version and performs no
write. `ExpiresAt` always retains the original natural deadline.

One existing-coordinator commit stores terminal state/version, reason, canonical
`identity.organization.expire_invitation` audit (standard retention),
`invitation.expired.v1` event and command effect. The pending-row fence is shared
with acceptance, so every outstanding old proof loses authority without changing
membership or organization epochs. Audit/outbox failure rolls the terminal
effect back. This neither recalls delivery nor rotates or reissues any proof.

Retain the original `PreparedInvitation` for exact keyed retries; changed reason
is changed command intent. Persist its safe `Recovery()` handle before execution.
After an unknown COMMIT, `Recover` authenticates the original current
owner/administrator and rechecks native session/member/scoped authority after
disclosure callbacks. No original proof, regenerated command or second journal
is needed. Terminal expiry does not restore authority after the natural deadline.

### Recipient invitation rejection

Install `InvitationRejectionMigrationSource` at an unused permanent version after
the cancellation migration before enabling `InvitationService.PrepareReject`.
The additive schema preserves pending/accepted/cancelled rows; older binaries
fail closed when reading the new rejected state. The current authenticated,
intended verified recipient supplies `InvitationRejectRequest` with exact
organization/invitation versions. No membership, administrative actor override
or invitation proof is accepted as recipient authority.

`Execute` uses the existing coordinator and current session/directory fences.
One commit changes only the pending invitation to its next rejected version and stores
the canonical `identity.organization.reject_invitation` audit,
`invitation.rejected.v1` event and command effect. Retention is `standard`, as
declared by the canonical SECURITY_EVENTS invitation profile; prior send/accept
retention is unchanged. Organization/membership authority is not advanced.
The original capability may remain cryptographically valid, but its native
pending-row fence cannot authorize acceptance after rejection. Acceptance and
rejection serialize through the same existing tenant/organization transaction.

Retain the original `PreparedInvitation` for keyed retries and persist its safe
`Recovery()` handle before execution. An unknown COMMIT response must be resolved
through `Recover` with a current genuine recipient session, without a proof,
new command ID or reissue. Listing/get surfaces return only safe terminal
metadata. Rejection itself does not resend, explicitly expire or recall delivery.

### Pending invitation cancellation

Install the forward-only `InvitationCancellationMigrationSource` at a permanent
version after all already selected organization migrations before calling
`InvitationService.PrepareCancel`. Installed invitation migration bytes remain
unchanged; existing pending/accepted records and original issuer custody survive
the upgrade. `InvitationCancelRequest` selects exact organization and invitation
versions and current owner/administrator authentication. Recipient email removal
or suspension does not by itself block cancellation.

Execution uses the existing risk/coordinator/current-session, organization,
membership and scoped-authority owners. It atomically advances the live pending
issued version to its next cancelled version, persists the required standard-retention
`identity.organization.cancel_invitation` audit and `invitation.cancelled.v1`
outbox event, and records the original result. It neither sends another message
nor consumes/reissues a capability. An already queued/sent invitation may still
arrive, but its proof cannot authorize acceptance. Acceptance independently requires
the exact current pending issued version;
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

### Current recipient listing

`InvitationService.ListMine` implements the distinct
`identity.organization.invitation.list-mine` action. It authenticates the human
recipient through the existing session owner, reads that user's current verified
email identifiers through the native directory owner, and evaluates current
self-list policy on `identity.user`. It does not require organization membership
or reuse administrator `Get`/`List` or delivery-status authority.

All retained invitations in supported lifecycle states with the exact current
recipient user and verified identifier ID/version are visible; pending records
project expired at exclusive expiry. Removed, unverified or superseded identifier
versions cannot reveal historical invitations. Organization membership and retained
organization status do not filter this safe history: listing reveals no organization
view or acceptance grant, and later acceptance still enforces current organization
authority. Unknown future persisted states fail closed rather than disappearing.

Pages contain only `Invitation` metadata, no address, delivery ciphertext/status,
capability or bearer. Limit is1–200. The scope-bound opaque cursor uses C bytewise
invitation-ID order; installed `PRIMARY KEY(tenant_id,invitation_id)` makes that
key unique even across organizations within one tenant. It is not a snapshot:
earlier additions require restarting. Both policy callbacks are followed by live
session and exact directory/identifier/page revalidation without renewing original
freshness. Late cancellation or authority changes return no partial page.

Install `InvitationRecipientIndexMigrationSource` at a permanent later version
before selecting this read. It creates the recipient/identifier/version/keyset
index concurrently, outside a transaction, without rewriting installed migrations
or rows. An interrupted invalid build must be inspected/reconciled through the
migration owner before activation; it is not hidden by `IF NOT EXISTS`.

The query supplies at most128 verified-identifier partitions from the directory's
existing limit. Each partition emits at most Limit+1 candidates before merging
at most25,728 candidates into a final <=201-row page. The exact-prefix index avoids
filtering unrelated historical identifier versions; context still bounds work
under MVCC churn or adverse planner conditions. It adds one retained immutable-key
index entry per invitation, without indexed mutable lifecycle/delivery columns.
This costs storage and insert/delete maintenance; no existing index is removed.

The isolated plan regression captures SQL/bindings from the actual public read,
compares normal-planner scans with and without only this index on20,003 controlled
history rows, and records tuple/buffer work plus heap/index sizes. Those added rows
are a storage-volume fixture, not issuance evidence. This proves that selected
access path and populated rollout, not deployed latency, global concurrency,
production frequency, future retention growth or production write cost.

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
`Teams.LifecycleVersion: 1`. Direct custom roles use their separate explicit
profile; its explicit team-binding option adds inherited permissions. Active
selection and HTTP composition remain unselected.

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

`TestOrganizationGenuineHTTPConsumer` adds the published optional
`go-identity/http/organization` leaf over the actual `OperationService`, without
an application adapter. Two users take the same genuine public Reference
signup/verification/sign-in path, then use their issued opaque sessions as
strict Authorization bearers over HTTPS. The selected feature supplies only
create/get/member-list/add/remove; omission supplies no routes or OpenAPI paths.
The case checks original keyed retries, changed-intent conflict, exact non-keyed
repeat removal, last-owner denial and current revoked-session denial. Each
successful HTTP result is matched against fresh native original recovery and
its real journal, domain effect, protected audit and lifecycle outbox rows.
Administrative admission uses the genuine PostgreSQL strict atomic backend and
native atomic schema; keyed retries still consume distinct HTTP debit records.
Actual responses are validated against the selected structured OpenAPI schemas.
Run this bounded case with
`go test -tags=integration -run '^TestOrganizationGenuineHTTPConsumer$' .`
against the same task-owned-cluster requirement above. This is public leaf/native
consumer proof, not Reference startup composition, browser/active-selection
support, invitations, teams or complete identity-platform qualification.

Root and adapter are independently releasable experimental modules. Public pins
must refer to published commits; permanent local replacements are unsupported.
See the [root API/exclusions](../README.md), [security](../docs/security.md) and
[release notes](CHANGELOG.md).
