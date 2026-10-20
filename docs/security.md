# Experimental security boundary

The selected explicit-organization profile implements create/read and membership
admission/static-role-update/list/removal. It is not a stable release or complete organization unit.
The opt-in membership-only team profile adds bounded creation, current-member
admission/removal and team/member/mine reads. It confers no independent roles or
permissions. Native commits fence actor and compatible target authority and
advance both the organization epoch and the directly changed subject's scoped
authorization epoch; reads repeat live session/member admission after policy.
Bindings retain the organization-member version, so removal/re-admission cannot
resurrect old teams. Zero team configuration advertises no team operations.
The controls below distinguish these finite profiles from later requirements.

The optional [direct custom-role profile](dynamic-roles.md) permits only exact
registered application permissions within a deployment ceiling. Current static
owner/admin management authority remains independent; an assigned role cannot
become an owner or grant organization-management access. Explicit deny wins and
unknown statements fail closed. Every check requires the current organization
policy epoch; removal/readmission cannot revive old direct bindings. Explicit
`TeamBindingsVersion: 1` additionally evaluates compatible current team bindings,
with deny precedence across both paths. Removed or terminally deleted teams and
stale organization admissions grant nothing; team roles confer no management
authority. Activation requires the forward migration and terminal team lifecycle.

## Selected profile

Public calls use the real native stateful opaque SessionService and external
authorization policy. Only verified single-factor password bearer sessions are
selected. Optional organization, factor and passkey authority is rejected, not
dropped. An explicit ID grants no access: every read checks current active
membership; mutation and final commit recheck original session/native authority.
Target admission uses the exact active directory aggregate/version under the
existing Work lock, separately from actor/session authority.

Membership removal advances organization-scoped subject authority and retained
member versions, never unrelated global user/credential epochs. No shared-cache
invalidation is claimed. Tenant-serialized writes protect cardinality and the
last active owner, including competing static role demotions. Owners are the
selected static profile's recovery administrators. Only owners may grant or
demote owners; ordinary administrators cannot mutate owners or escalate to owner.
The native Coordinator exclusively owns command claims,
rollback, commit, replay and scoped recovery. Domain, scoped authority, audit and
lifecycle outbox changes share its transaction. Participant effect rows are
exact-command evidence, not a second journal. Unknown outcomes require primary
reconciliation rather than another command ID.

Bearer-bearing values reject automatic serialization and redact formatting.
Do not log names, bearer/session material or configuration keys. Persist only
safe recovery scope. The transport must resolve a trusted canonical client IP.
Contexts are bounded, key maps copied, pools borrowed and background work absent.
External policy callbacks must honor cancellation.

## Assets and trust boundaries

The planned core will protect organization, membership, role, team, ownership,
domain-claim, invitation, active-session, policy-version, audit, and durable
transition state. Trust boundaries will include commands and queries,
caller-supplied stores and units of work, delivery hooks, domain-proof readers,
session and authorization integrations, capability links, and protocol or
persistence adapters.

Applications own transport security, external policy, pool/key lifetimes,
canonical-ID validation and user interfaces. Existing native owners supply
sessions, protected counters, audit and transaction authority; the adapter must
not infer those capabilities from ambient process state.

## Requirements for later profiles

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

**ORGANIZATION-RISK-001 — incomplete full-unit qualification**

- **Severity:** critical if treated as deployable.
- **Disposition:** release blocker; not accepted for production.
- **Owner:** go-organization maintainers.
- **Rationale:** full invitation/team-role qualification, domain proofs,
  archive/delete commands, active selection, cache
  closure, SSO/SCIM, MFA/passkeys and HTTP/browser transport are unselected.
- **Mitigation:** keep the modules experimental; do not infer those controls
  from reserved database states or the historical goal.
- **Review condition:** reassess after the affected profile has actual native
  integration evidence, current dependency/security checks and independent
  complete-diff review. Full identity-platform qualification remains separate.

Choose the next guide in the [documentation index](README.md)
or return to the [repository entry](../README.md) for installation and ownership.
