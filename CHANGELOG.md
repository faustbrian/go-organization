# Changelog

## Unreleased

- Add a neutral natural-repeat invitation-expiry request binding exact invitation
  and organization versions and a registered non-secret reason, without a key,
  caller command or recipient proof. Repetition requires actual matching original
  metadata and current original-manager/session authority; terminal state alone
  is not a receipt. Existing explicit expiry APIs remain unchanged; this contract
  alone enables no durable initiating workflow or HTTP route.

- Add a neutral original-key owner-transfer request binding the existing member,
  organization and both membership versions and complete original password
  proof. Bounded validation and redacted custody confer no authority. Exact
  transfer bindings can use neutral original-outcome recovery syntax; existing
  preparation and native recovery APIs remain unchanged. This contract alone
  enables no durable initiating workflow or HTTP route.

- Add a neutral natural-repeat self-leave request and exact-self original-outcome
  recovery syntax, without a target, key or caller command ID. Bounded validation
  and redacted custody grant no execution or disclosure authority. Existing
  explicit leave and legacy recovery APIs remain unchanged; these contracts
  alone enable no native workflow or HTTP route.

- Add session-authenticated advisory slug availability in the current tenant,
  without membership or management requirements, organization metadata or a
  reservation promise. Optional `OrganizationSlugReader` preserves existing
  repositories; current policy/session/source checks deny on withdrawal,
  outage or expired original authority. Native readers must include archived
  rows in tenant-local occupancy; create/update uniqueness remains authoritative.

- Add a neutral natural-repeat invitation-rejection request without a client key,
  caller command or invitation proof. Repetition requires actual original
  metadata and current verified intended-recipient authority, not membership or
  manager permission or success inferred from terminal state. Existing explicit
  rejection APIs remain unchanged; this contract alone enables no durable
  initiating workflow or HTTP route.

- Add a neutral natural-repeat invitation-cancellation request without a client
  key, command or recipient proof. Repetition requires actual original metadata
  and current manager authority, never success inferred from a terminal row.
  Existing explicit cancellation APIs remain unchanged; this contract alone
  enables no durable initiating workflow or HTTP route.

- Add original-key invitation-resend request and neutral outcome/delivery-state
  contracts. Preserve the fixed recipient, role and original exclusive expiry;
  retries classify the original successor without reissuing or redelivering it.
  Existing explicit native APIs are unchanged; these contracts alone enable no
  durable execution or HTTP route.

- Add keyed `LifecycleOperationRequest` for exact-version owner archive/restore
  with complete original action-proof intent, and exact original lifecycle
  recovery syntax. Credentials and initiating keys remain non-serializable;
  validation does not authenticate signed proof, current authority or expiry.
  Matching retries must retain original command/proof observations, never
  prepare again. Existing explicit lifecycle APIs are unchanged; these neutral
  contracts alone add no durable execution, HTTP or external cascade profile.

- Add opaque `PreparedInvitationAcceptance` for two-phase native preparation,
  original rate admission and later exact execution. Transports can complete
  pre-handler gates before executing without rebuilding preparation or renewing
  authority. Existing once-only callback and original recovery contracts remain
  unchanged; this interface adds no journal, execution engine or HTTP route.

- Add non-consuming syntax validation and neutral admission/recovery custody for
  once-only invitation acceptance. A transport gate receives authenticated
  original challenge metadata before native execution; explicit recovery retains
  the full original binding and current authentication. No request key, proof
  redisclosure, bare-ID lookup or HTTP route is introduced; existing explicit
  preparation/execution APIs remain unchanged.

- Add keyed `UpdateMemberOperationRequest` for static member-role replacement at
  exact organization/member versions, including owner transitions and original
  outcome recovery syntax. Credentials and initiating keys remain opaque,
  non-serializable custody; native current authority and last-owner checks are
  unchanged. Existing explicit preparation APIs remain compatible; these neutral
  contracts alone do not enable a durable operation or HTTP route.

- Add `InvitationSendOperationRequest` for original-key invitation send without
  caller-allocated command/invitation IDs or submitted addresses. Matching retries
  retain original recipient/version intent and cannot renew authority or proof;
  existing explicit preparation and acceptance contracts remain unchanged.

- Add keyed `UpdateOperationRequest` for bounded name/slug replacement with an
  exact organization version, plus original Update outcome recovery syntax.
  Credentials and the required key remain non-serializable custody; existing
  `UpdateRequest` and preparation APIs are unchanged. These contracts do not
  enable a durable operation or HTTP route by themselves.

- Add transport-neutral operation requests for keyed organization creation and
  member admission, naturally repeatable exact-version member removal, and
  current-authorized original-outcome recovery. Syntax validation is bounded
  and credential custody cannot be serialized; existing preparation APIs remain
  unchanged. Durable operation implementation belongs to the native adapter.

- Add opt-in organization-owned domain evidence with an explicitly trusted
  bounded observer, exact scope/version/time binding and authoritative current
  reads. Original-command recovery preserves historical proof without renewing
  expiry or repeating observation; revocation and archive retirement are terminal.
  Reservations alone still confer no domain ownership or SSO routing authority.

- Add opt-in owner-only native archive/restore with fresh action-bound password
  proof, exact organization versions and current-authorized original recovery.
  Archive denies native child authority and atomically cancels pending invites;
  restore preserves all terminal child states. Hard deletion and external
  integration cascades remain separate unsupported profiles.

- Add opt-in team custom-role assignments and current direct-plus-team permission
  evaluation with shared deny precedence. Exact team binding discovery supports
  fresh clients; deleted teams and stale organization admissions grant nothing.
  Existing direct-only configuration remains unchanged.

- Expose exact member role-binding snapshots through authenticated role reads,
  including absent and revoked versions for fresh-manager revoke/reassignment.
  Stored assignment state remains separate from current membership authority.

- Add opt-in bounded custom roles and direct-member assignments with exact
  registered action/resource permissions, explicit-deny precedence, current
  organization policy fences and terminal deletion. Custom roles cannot grant
  owner/administrator management authority.

- Add opt-in owner/administrator domain reservation, authenticated own-claim
  reads and exact-version withdrawal. Explicit ASCII canonicalization and
  bounded retained claims preserve immutable withdrawn identities; reservations
  are not ownership proof and do not authorize SSO routing.

- Add owner/administrator resend preparation for an exact pending invitation.
  Preserve its recipient, member role and original deadline while selecting the
  next issued version. `Invitation.IssuedVersion` distinguishes later pending
  generations from their terminal transitions; zero retains legacy version1.

- Add owner/administrator static member-role updates with exact organization
  and membership versions, final-owner protection and current role authority.
  Only owners may grant or demote owners; unchanged roles conflict.

- Add owner/administrator invitation expiry with exact versions and registered
  reason codes. Explicit expired version2 is terminal and distinct from natural
  deadline projection at version1; prior invitation APIs remain unchanged.

- Add exact-version invitation rejection for the authenticated intended verified
  recipient without membership or invitation proof, with terminal rejected metadata.

- Add current-recipient invitation listing with bounded stable pages, explicit
  lifecycle visibility, current verified-identifier binding and late-authority
  revalidation, without organization membership or sensitive delivery material.

- Add exact-version pending invitation cancellation for current owners and
  administrators, with terminal cancelled metadata and original-command custody.
  Recipient proof and current recipient credentials are not cancellation authority.

- Add authenticated current-subject organization listing with bounded visible
  pages, stable scoped cursors, per-organization policy filtering and post-policy
  authority/freshness revalidation. The repository list capability is additive.

- Add explicit self-only organization leave with exact organization policy
  version, last-owner protection and current membership disclosure semantics.
  Leaving never revokes unrelated global password/session authority.

- Add an atomic owner-transfer profile for an existing active member, with
  exact organization and both membership versions. The former owner becomes
  an ordinary member; both scoped authority epochs advance without changing
  unrelated global credentials or increasing the owner count.

- Add opt-in exact team reads, versioned bounded name replacement and terminal
  deletion. Retired team IDs cannot be reused; existing membership-only
  configuration and command framing remain unchanged until lifecycle selection.

- Add an opt-in, bounded team-membership profile with owner/administrator
  creation and membership changes, authenticated team/member/mine reads and
  exact versions. Team bindings confer no independent permissions; removed
  organization admissions cannot revive old team membership on re-entry.

- Add bounded owner/administrator organization name and slug update preparation
  with exact organization versions, current action policy and explicit no-op
  conflict semantics; preserve memberships and all other fields.

- Repeat current external organization action policy before prepared execution,
  preserving original session/invitation expiry and denying before protected
  work when policy changes, expires admission or cancels the operation.

- Add selected storage-neutral invitation send/accept preparation for existing
  verified email recipients and member-only grants, plus owner-only safe
  metadata reads. Native capability/delivery composition is required for
  durable execution; resend/cancel and recipient listing remain unselected.
- Preserve invitation aggregate versions and the original invitation ID in
  committed/unknown outcomes without changing existing membership receipts.
- Add experimental explicit-organization create/read and membership
  admission/list/removal policy with real session admission, scoped permission
  checks, optimistic versions, bounded limits and last-owner protection.
- Define immutable adapter transaction/recovery handoff and explicit durable
  outcomes; commands and authentication reject automatic serialization.

This is an initial experimental profile, not a stable API or full organization
unit release. Use the optional native PostgreSQL module for durable operations.
