# Changelog

## Unreleased

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
