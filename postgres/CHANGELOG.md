# Changelog

## Unreleased

- Add opt-in team-role bindings through the existing role actions/coordinator.
  Install `TeamRoleBindingMigrationSource` after dynamic roles and terminal team
  lifecycle before selecting `DynamicRoles.TeamBindingsVersion: 1` on both
  core and contributor. Bindings, team/policy epochs and protected effects commit
  atomically; current compatible members inherit direct-plus-team deny precedence.

- Require current manager/session authority for terminal custom-role mutation
  replay and expose scoped exact binding discovery for fresh native clients.
  Revoke/reassignment no longer requires retained application version history.

- Add opt-in durable custom-role CRUD, direct member assignment/revocation and
  current primary permission checks using the existing authorization engine.
  Install `DynamicRoleMigrationSource` before enabling identical `DynamicRoles`
  policies in core/contributor configuration; the risk owner must classify
  role assignment/revocation as privileged mutations. Role changes, policy
  epochs, scoped binding authority, protected audit and lifecycle effects share
  the existing coordinator transaction and original-command recovery.

- Add opt-in native domain reserve/current-get/withdraw custody with global
  cross-tenant active-name uniqueness, retained immutable tombstones and atomic
  organization epoch, protected audit, lifecycle and original-command recovery.
  Install `DomainClaimMigrationSource` and use a risk supplier with explicit
  privileged reserve/withdraw classifications before enabling `DomainConfig`.
  This profile does not establish domain ownership or SSO routing authority.

- Add current owner/administrator invitation resend with atomic predecessor
  supersession, one successor grant/encrypted delivery and unchanged recipient,
  member role and deadline. Install `InvitationResendMigrationSource` after
  expiry before selecting resend. `ExecuteResend`/`RecoverResend` expose only
  the original command's bounded delivery metadata, retaining known committed
  receipts if a later metadata read fails; retries/recovery never reissue.

- Add native static member-role updates with atomic organization/member/scoped
  authority versions, canonical protected audit/lifecycle and exact recovery.
  Existing schemas suffice. Self-demotion history requires current membership
  and policy; other-target history still requires current management authority.

- Add native explicit invitation expiry, atomic canonical audit/event and
  reason custody, acceptance exclusion and original-command recovery. Install
  InvitationExpiryMigrationSource after rejection and use the risk owner's
  privileged expiry profile before enabling it; unsupported risk profiles deny.

- Add native recipient invitation rejection with atomic terminal version,
  canonical audit/outbox effects and proof-free original-command recovery.
  Install InvitationRejectionMigrationSource after the cancellation migration
  before enabling rejection; older binaries fail closed on rejected metadata.

- Add genuine current-recipient invitation listing without organization
  membership, with lifecycle-complete safe pages and late session/directory
  revalidation. Install the additive concurrent recipient-index migration before
  selecting the read; prior schemas and invitation mutation framing are unchanged.

- Add native pending invitation cancellation with required canonical audit and
  lifecycle effects, accept/cancel exclusion and current-authority metadata
  recovery. Install the additive InvitationCancellationMigrationSource after
  existing migrations; historical migration bytes and issuer custody are unchanged.

- Add current-subject organization listing through primary membership/scoped
  authority owners and existing indexes. Initial policy denials are omitted;
  late withdrawal, authority errors and scan-cap violations disclose no page.
  Existing schema and mutation APIs remain unchanged.

- Add native self-leave through the existing coordinator, atomic membership
  tombstone/scoped authority and organization policy epochs with protected
  removal audit/outbox effects. Existing schemas suffice; readmission cannot
  revive old team bindings or repeat the historical departure.

- Add ownership transfer through the existing coordinator, conserving the
  owner count and atomically advancing both memberships, scoped authorities,
  organization policy epoch and protected audit/lifecycle effects. Exact
  metadata-only recovery remains available to the current former-owner member.

- Require independently known-empty current actor and target MFA generations
  for the selected single-factor ownership transfer, fenced through final
  commit even when first factor activation leaves an existing SFA session valid.

- Add optional native team get/update/delete through the existing coordinator.
  Install TeamLifecycleMigrationSource before LifecycleVersion 1 activation;
  live-row deletion denies former bindings without per-member fan-out, preserves
  terminal identity/recovery and rejects old-writer ID resurrection.

- Revalidate actual session, organization/member role and policy/scoped authority
  after recovery-policy callbacks before disclosing retained outcomes, including
  the shared organization metadata-update recovery path.

- Add native optional teams and membership through the existing coordinator,
  with explicit startup quotas, current session/member authority, policy and
  scoped authorization epochs, protected audit/lifecycle effects and exact
  outcome recovery. Install the additive TeamMigrationSource before enabling
  teams; zero configuration preserves existing operations and registrations.

- Add native organization name/slug updates through the existing coordinator,
  with current owner/administrator authority, tenant-unique slugs, expected
  versions, atomic protected audit/lifecycle effects and exact-command recovery.
  The existing schema suffices; membership and global authority are unchanged.

- Add native owner-send and existing verified-recipient acceptance through the
  sole identity Coordinator, shared one-use capability and encrypted delivery
  owners. Acceptance atomically updates membership/scoped authority and emits
  separate invitation and actual-membership lifecycle events.
- Add persistable safe invitation recovery with current genuine authentication,
  including new-service recovery after a lost commit acknowledgement. Metadata
  never returns proof custody; definitive failed acceptance terminal-releases
  the original grant rather than making it reusable under a new command.
- Preserve original send organization correlation in the shared immutable
  preparation declaration so interrupted sends recover before a domain row
  exists, without treating caller-supplied organization IDs as authority.
- Add an additive private issuer-identity migration; legacy read-only invitation
  rows remain NULL and cannot accept inferred custody. Native construction now
  requires explicit independent delivery-status authorization configuration.
- Add a forward-only invitation persistence migration for exact recipient,
  organization, member-only grant, lifecycle and durable delivery-effect fences;
  preserve the original installed membership migration unchanged.
- Add owner-only invitation metadata reads through real current delivery status
  authorization and verified recipient preparation through the identity owner.
  These read/persistence prerequisites do not themselves issue or consume links.
- Add experimental native PostgreSQL create/read and membership admission,
  listing/removal through existing identity Coordinator, counters, audit,
  lifecycle outbox and scoped authorization owners.
- Add tenant-serialized cardinality/last-owner protection, durable tombstones,
  exact-scope recovery and explicit ambiguous outcomes.
- Classify protected quota and last-owner rejections as authorization denials
  in caller outcomes, retained command results and audit, not dependency failures.

Install native owner migrations plus the organization source before use. Only
the explicit-ID uncached password/bearer profile is selected; later organization
features and full identity-platform qualification remain pending.
