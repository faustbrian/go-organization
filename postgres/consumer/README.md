# Genuine organization PostgreSQL consumers

This test-only nested module preserves the real signup, verification, password
signin, native organization and encrypted-delivery consumers. It consumes the
published native adapter and HTTP leaf through normal authenticated public pins,
with no workspace replacement or synthetic authentication/domain store.

Reference/bootstrap and HTTP dependencies belong here, not in the native
adapter's production module. This keeps the production dependency direction
`Reference -> HTTP/native organization`, while these independent tests can
compose all three. Existing native-only fixtures and unit/integration tests stay
in the parent module; small unchanged private helper blocks are retained in each
test package where needed. Test names, profile selection, outcome/effect
assertions and cleanup are unchanged.

From this directory, use the repository's pinned Go toolchain and task-owned
disposable `GOCACHE`, `GOMODCACHE` and `GOTMPDIR`. Supply an authorized isolated
UTF-8 PostgreSQL instance with `GOLIB_ORGANIZATION_TEST_POSTGRES_DSN`; each test
creates and removes its own database and roles. Compile all integration profiles
with `GOWORK=off go test -tags=integration -run '^$' ./...`, and select the affected
genuine journey with `GOWORK=off`, its existing
`TestOrganizationGenuine*Consumer` name and `-race`. Workspace mode would override
the published adapter pins and is not public-consumer evidence.
Run ordinary parent-module tests separately. No new runner or workflow is needed.

These consumers prove their selected existing native profiles, not full M22,
external lifecycle cascades or a stable organization release. See the
[native adoption and security notes](../README.md).
