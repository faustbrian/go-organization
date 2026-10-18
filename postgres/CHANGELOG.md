# Changelog

## Unreleased

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
