# Planned security model

This repository contains planning metadata only. It has no runtime package,
public API, parser, persistence adapter, network operation, background work, or
supported release. The controls below are release requirements, not claims
about implemented behavior.

## Assets and trust boundaries

The planned core will protect organization, membership, role, team, ownership,
domain-claim, invitation, active-session, policy-version, audit, and durable
transition state. Trust boundaries will include commands and queries,
caller-supplied stores and units of work, delivery hooks, domain-proof readers,
session and authorization integrations, capability links, and protocol or
persistence adapters.

Applications will continue to own user authentication, transport security,
route and database authorization, tenant isolation, persistence transactions,
rate limiting, audit delivery, session storage, and user interfaces. The core
must not infer those capabilities from ambient process state.

## Required controls before implementation or release

- Validate every untrusted command through byte, field, item, metadata, list,
  pagination, and diagnostic ceilings before allocation or normalization.
- Bind authorization decisions and capabilities to the exact tenant,
  organization, principal, session, recipient, purpose, and policy version;
  reject stale or mismatched scope without disclosing record existence.
- Make invitation acceptance single-use, expire capabilities, supersede old
  invitations on resend, and keep raw capability values out of storage,
  errors, logs, traces, fixtures, snapshots, and generated evidence.
- Make ownership transfer, last-owner protection, membership and role changes,
  invitation consumption, and lifecycle transitions atomic through
  caller-owned persistence; expose classified durable-outcome ambiguity rather
  than retrying blindly.
- Revalidate session-scoped active organizations and fail closed when
  membership, organization state, or policy versions change.
- Require domain proofs to be unique, current, bounded, expiring, and
  revocable; treat unavailable or indeterminate proof state as non-authorizing.
- Require a non-nil caller context for external work, propagate cancellation
  and deadlines, close every acquired resource, and start no unowned goroutine.
- Copy mutable inputs, make concurrency ownership explicit, use typed bounded
  metadata rather than open maps, and bound hooks and callbacks independently.
- Bind lifecycle and authorization decisions to hostile, replay,
  cross-organization, enumeration, fixation, fuzz, race, resource, dependency,
  source-scanner, and direct-consumer evidence.

## Release disposition

**ORGANIZATION-RISK-001 — unimplemented authorization and lifecycle boundary**

- **Severity:** critical if treated as deployable.
- **Disposition:** release blocker; not accepted for production.
- **Owner:** go-organization maintainers.
- **Rationale:** no executable contract currently enforces the planned
  organization, authorization, capability, session, transition, cancellation,
  or resource invariants.
- **Mitigation:** keep the module planned, unpublished, non-installable, and
  non-releasable; consumers must use an independently supported implementation.
- **Review condition:** reassess only after implementation, a complete threat
  model, executable hostile and concurrency evidence, scanner results, API and
  migration policy, and independent Tier C review are present.
