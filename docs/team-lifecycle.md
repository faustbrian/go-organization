# Selected team lifecycle

The optional native profile provides `GetTeam`, `PrepareUpdateTeam` and
`PrepareDeleteTeam` for current owners/administrators. Set identical
`Teams.LifecycleVersion: 1` on the core and native contributor only after applying
`TeamLifecycleMigrationSource` after the existing team migration. Zero keeps the
delivered membership-only profile, configuration JSON and feature framing
unchanged; it exposes no new lifecycle mutations. No HTTP route is selected.

Name replacement uses the existing 1..256-byte UTF-8, trimmed, control-free
contract. Both organization and team versions must match; identical names
conflict without effects. Update advances both versions without changing role,
membership or scoped-authorization bindings. Protected commit and historical
recovery retain native current-session, actor/member and scoped-authority checks.

Deletion advances the organization policy epoch and retains a terminal team-ID
tombstone with its final team version. It removes only the live team row; former
member bindings remain structurally retained but cannot authorize or appear in
team/mine views. No per-member authorization fan-out establishes denial. Ordinary
members, organization re-admission, retries and ID reuse cannot restore the team.
The lifecycle profile counts retained team identities against `MaximumTeams`;
deleting an ID does not reclaim that identity slot. Retention of historical
membership/audit data remains a separate operator concern.

The forward migration does not rewrite installed migration bytes or infer new
membership. Existing live IDs are preserved. Existing reader SQL sees no deleted
team row, and an insert guard rejects retired IDs even for the previous writer
shape. Apply this schema before enabling deletion; the migration and failed
commands are transactional. Lost commit acknowledgements use the exact existing
coordinator recovery binding, never a recreated team or a second retry identity.

## Local product-catalog reconciliation

The complete organization goal explicitly requires team **get**, but the planning
operation table lists list/update/delete without a callable get row. This profile
defines storage-neutral `identity.organization.team.get` as an authenticated,
manager-only exact read. It adds no inferred HTTP method/path or active-team API.

Name-only update uses declared `identity.organization.team.update` and protected
audit `identity.organization.update_team`. It emits `team.updated.v1`, an additive
lifecycle spelling for metadata changes omitted from the original event table;
it does not mislabel a name change as `team.membership_changed.v1`. Deletion uses
declared `identity.organization.team.delete`, protected audit
`identity.organization.delete_team`, and `team.deleted.v1`.

This is not dynamic roles, active-team selection, federation, HTTP composition,
full M23 completion or full-unit release qualification.
