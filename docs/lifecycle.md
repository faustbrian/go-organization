# Selected native archive and restore

This explicit native-only M22 profile is not hard deletion, complete composed
archive, or full organization qualification. Active-session selection,
organization keys, SSO/SCIM and external integration links remain unselected.
No absence of arbitrary separately installed external schemas is attested.
A future external composition must enlist its actual owner; these APIs do not
claim asynchronous cascade closure or external write disablement.

## Selection and use

Apply `LifecycleMigrationSource` after all installed organization migrations.
If invitations are installed, include the existing cancellation, rejection,
expiry and resend chain first. The additive migration preserves predecessor
bytes, existing state, child IDs and every tombstone. It permits system
cancellation of naturally expired pending invitations at real database time.
Installing invitation storage later requires an appropriately ordered lifecycle
migration before activation; an incompatible schema fails closed.

Select identical `LifecycleConfig{Version: 1, ProofAudience: ...}` on core and
contributor. Supply separate actual password `ActionPrimarySource` values as
`ArchivePrimary` and `RestorePrimary`, matching the respective canonical
actions and audience. Use the password owner's lifecycle reauthentication
forward migration and an MFA supplier supporting these self-only actions.
Missing or mismatched dependencies reject construction, not downgrade proof.
Zero selection preserves previous operation advertisement and command framing.

Current owners use `GetLifecycle` to discover active/archived state and the
exact policy version. Ordinary `Get`, membership, team, permission, invitation
and domain authority continue requiring an active organization. Administrators,
custom roles, ordinary members, foreign tenants and revoked sessions cannot
discover or restore archived organizations through the lifecycle API.

Obtain a fresh password reauthentication proof for the exact archive or restore
action. `LifecycleRequest` carries the current organization version, stable
command ID and a 1..64 visible-ASCII reason code. The native preparation
authenticates the signed original proof for the current owner/session/action/
audience, with the sensitive-operation 15-minute ceiling and independently
known-empty current MFA state. Visible proof fields alone confer no authority.
Then use `PrepareArchive` or `PrepareRestore`, followed by ordinary `Execute`.

## Authority and child disposition

Archive atomically changes the parent to archived and increments the organization
policy epoch. Every new native authority check requires active primary state;
warm services and commands prepared before archive cannot keep granting access.
Pending invitations, including naturally expired pending rows, are terminally
canceled in the same transaction using their existing state/version fence.
Capability secrets are neither read nor rewritten. Existing terminal invitation
states remain unchanged.

Memberships, teams, direct/team role assignments and domain reservations are
retained but cannot establish authority while archived. Slugs/domains are not
released for takeover. Restore advances the policy epoch again and permits
current checks against surviving active child state. It never recreates removed
memberships, deleted teams/roles, withdrawn claims or canceled/revoked invitation
grants. Old prepared commands and old policy versions remain stale; restoration
is not a credential refresh or a new session.

All selected local effects, signed proof consumption, protected audit and
`organization.archived.v1`/`organization.restored.v1` share the existing identity
coordinator Work. Operations obey bounded deadlines; a failed local cascade
rolls back rather than leaving partial authority changes. No background cascade
engine, alternate transaction owner or external completion claim is introduced.

## Recovery

Retain the exact preparation and safe original `Recovery` handle. Known rollback
does not consume the proof or advance state, but the failed command remains
terminal. Only after a known rollback may a newly admitted command reuse a
still-current, unconsumed proof. A lost COMMIT response is unknown until the
existing coordinator reconciles that original command; do not issue a new
archive/restore command as a retry. A fresh genuine session of the
original actor may recover safe historical metadata while still a current
owner, including while archived. Terminal `Execute` replay repeats current
session/owner/action checks. Recovery never replays effects or restores grants.

Hard deletion, legal-hold cleanup and complete asynchronous external cascades
remain distinct full-scope obligations, not aliases for archive/restore.
