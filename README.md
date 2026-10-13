# go-organization

> **Status: planned.** This repository does not currently provide an
> installable package, a released version, or a runtime API.

`go-organization` reserves the planned Golib boundary for organizations,
memberships, invitations, teams, role assignments, ownership transfer, domain
claims, and organization lifecycle. The plan keeps those concepts separate
from federation protocols, persistence, billing, and application concerns.

## Planned responsibility

The future root package is intended to own storage-neutral organization policy,
records, lifecycle transitions, domain claims, and explicit coordination
through caller-supplied resources. Its contracts remain proposals until they
are implemented, reviewed, verified, and released.

## Non-goals

The planned root boundary does not own:

- enterprise single sign-on protocol behavior or SCIM wire behavior;
- billing or user interfaces;
- session persistence or application authorization policy; or
- database clients, migrations, transactions, caches, or background workers.

Those concerns may become separate modules or compose existing Golib packages.
Their presence in planning material does not make them available here.

## Lifecycle and ownership

Implementation, hardening, and release have not started. The current module
declaration exists only so repository tooling can validate the planned module
identity, family, ownership, and lifecycle metadata.

The plan requires caller-owned configuration and runtime resources, copied
mutable inputs, context-bounded external operations, and no package-owned
background work. These are design constraints, not claims about released
behavior.

## Planning and verification

The [repository goal](docs/goal.md) and `modules.json` record the planning scope
and schema-v2 engineering inventory. Planned lifecycle state excludes this
module from installable and released consumer catalogs. The local
`make cohesion` target validates that boundary with the exact checksum-pinned
`go-library-tools` release declared in `.golib.yaml`.

Passing repository checks proves only that the planning scaffold and metadata
are internally consistent. It does not prove organization behavior or an API.

The [planned security boundary](docs/security.md) records the assets, trust
boundaries, required controls, and release blockers that any future runtime
must satisfy. See [SECURITY.md](SECURITY.md) to report a vulnerability
privately; no released version is currently supported.

Use Go 1.27.2 and the qualified public Tools v2.1.2 binary; the planned
module minimum remains Go 1.27.0. `make check`, `make ci` and `make fast-check`
validate configuration, repository structure, cohesion, offline specification
decisions, local documentation links and whole-tree/history secrets.
CI uses the same structural commands plus validated PR-base or push-before
changed-content secret checks on every change. Ordinary Required has a
five-minute job limit; changed secrets have a forty-second fatal timeout.
Scheduled/manual runs retain whole-tree secrets and online authority refresh.
`make check-full` explicitly preserves the previous full/online contract.
These commands do not run application tests or establish runtime/release proof.
See [contributing](CONTRIBUTING.md) for public tooling installation and scope.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## License

MIT. See [LICENSE](LICENSE).

## Documentation navigation

[Complete documentation map](docs/README.md#complete-documentation-map)

Use the [versioned ecosystem entry](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md) for package
selection. The [frozen compatibility cohort](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/compatibility-sets.md)
is separate from current package releases and unpublished source changes.
Adopting them does not silently update that cohort.
