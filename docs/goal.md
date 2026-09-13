# Goal: planned go-organization boundary

Status: planned

The coordination plan identifies `github.com/faustbrian/go-organization` as
the future storage-neutral owner of organizations, memberships, invitations,
teams, role assignments, ownership transfer, domain claims, and lifecycle
policy.

The source planning record is
`.ai/identity-platform/goals/organization.md` in the Golib coordination tree,
with SHA-256
`9660847150c7f90193c6bc7088f0fcb84971fe0a4e1957f5c8905635b8736e95`.
That record contains proposed contracts; it is not implementation evidence.

## Current planning acceptance

- Keep this repository visibly planned and absent from installable consumer
  catalogs.
- Record the frozen Service Edge family, organization capability, ownership,
  and delivery lifecycle in schema-v2 engineering metadata.
- Validate the metadata locally and in hosted CI with immutable,
  checksum-verified `go-library-tools` v1.4.0 tooling.
- Do not claim a public package identifier, installation path, runtime API,
  compatibility promise, or released behavior.
- Keep the module non-releasable until its security model is implemented with
  executable evidence for authorization, membership, invitation, ownership,
  session, persistence, cancellation, resource, and redaction boundaries.

## Deferred implementation

Source packages, nested modules, dependencies, API contracts, behavior,
hardening evidence, compatibility commitments, tags, and releases remain
outside this planning-only goal. They require separately authorized work and
their own executable acceptance evidence.
