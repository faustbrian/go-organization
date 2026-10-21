# Authenticated domain reservation custody

The additive [domain-evidence profile](domain-evidence.md) independently enables
organization-owned observed proof; this document describes reservation-only
configuration, whose behavior remains unchanged.

This opt-in profile reserves a canonical ASCII name for one exact active
tenant/organization. **A reservation is never proof of domain ownership.**
It cannot route SSO, verify an enterprise provider, or create a usable
`DomainProof`. Challenges, DNS/HTTPS observation, verification, expiry/takeover
and parent/child-domain delegation remain outside this selected profile.

## Configuration and canonicalization

Zero `DomainConfig` disables all three public operations. A selected config
requires a nonzero immutable `Version` and `MaximumClaims` from 1 to 10,000.
The quota includes every retained requested and withdrawn claim, so withdrawal
does not erase history or replenish the retained-storage budget. Choose the
budget deliberately; this profile provides no garbage collection or deletion.
Core and native contributor configs must match exactly.

`CanonicalDomain` is an explicit restricted input policy, not general IDNA
processing: it admits at least two ASCII letters/digits/hyphen labels, each
1–63 bytes without leading/trailing hyphens, up to 253 canonical bytes. The
final label must contain at least one ASCII letter (`example.a1` is admitted;
`example.123` is not). It lowercases ASCII and removes one terminal root dot.
Unicode, whitespace, wildcard labels, IP literals, ports, schemes, empty labels
and multiple terminal dots are rejected. Supplied ASCII A-labels are treated
as ASCII; no Unicode conversion or IDNA-conformance claim is made.

## Public sequence

1. Apply the native `DomainClaimMigrationSource` after the existing organization
   schema, before selecting `DomainConfig`. Use the risk supplier with explicit
   privileged reserve/withdraw operation classifications.
2. Authenticate a genuine verified password bearer session for the selected
   tenant. Current owners and administrators may manage and read custody;
   ordinary members, removed members and foreign-tenant sessions may not.
3. Call `PrepareReserveDomain` with a new immutable canonical `ClaimID`, the
   exact expected `OrganizationVersion`, `ClaimVersion == 0` and domain text.
   Preparation changes no durable state. Preserve the resulting prepared
   command; `Execute` atomically stores requested version1 and advances the
   organization epoch with protected audit, lifecycle and participant evidence.
4. Call `GetDomainClaim` with the organization and claim ID to read current
   own-organization custody. Policy callbacks confer no lease: session and
   primary membership/organization authority are checked again before return.
5. `PrepareWithdrawDomain` requires the same canonical name/ID and exact current
   organization/claim versions. `Execute` retains withdrawn version2. A later
   reservation requires a new claim ID; the old identity never becomes active.

The root service supplies adapter-neutral preparation and execution handoff;
native `postgres.Service` supplies the public durable composition. No caller
implements a coordinator, command journal, domain store or success classifier.
Mutation receipts retain the organization aggregate version; use authenticated
`GetDomainClaim` for current claim state, not a historical receipt as authority.

## Contention, admission and recovery

PostgreSQL globally arbitrates requested names across all tenants through one
partial unique index. Exact names are exclusive; parent and child names are
independent. Conflicts disclose neither competing tenant nor organization.
The per-organization retained-claim quota is checked under the existing
tenant/aggregate locks, not an unbounded cross-tenant lookup.

Final commit fences the original session interval, account, credential, global
and scoped authorization, active organization, current actor membership, policy
identity, and exact organization/claim versions. A stale or revoked source
cannot turn preparation or a lock wait into a fresh grant. Claim, aggregate
epoch, participant evidence, protected audit and lifecycle outbox roll back
together if any participant fails.

Preserve the original prepared command for exact replay. Reusing its command
ID with changed intent conflicts. Persist its safe `Recovery` metadata when
the process may end: a new native service can recover the original command
using fresh current owner/administrator authentication. Unknown means reconcile
that original command; do not invent a retry ID. Recovery never re-reserves,
withdraws again, performs external observation or renews proof freshness.
