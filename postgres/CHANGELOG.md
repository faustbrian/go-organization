# Changelog

## Unreleased

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
