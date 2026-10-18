# Changelog

## Unreleased

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
