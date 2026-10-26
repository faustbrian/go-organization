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

`TestOrganizationGenuineInvitationRejectOperationConsumer` and the independent
`TestOrganizationGenuineInvitationRejectWithdrawalConsumer` fixtures prove
natural recipient rejection without membership or manager/read authority.
They cover original and changed selectors, legacy NULL history, the independent
optional migration, predecessor denial, atomic audit/outbox rollback, actual
COMMIT-response loss, competing rejection/acceptance and fresh-session recovery.
Identifier withdrawal during either disclosure-policy boundary must actually
commit and deny the original receipt; fixture security epochs are never reset.

`TestOrganizationGenuineInvitationCancelOperationConsumer` proves naturally
repeatable cancellation with native-allocated command identity. It uses real
manager sessions, exact original selector/history, old-proof denial, restart
recovery, org:invite without org:read, late manager and recipient withdrawal,
atomic rollback, final COMMIT-response loss and competing cancellation/acceptance.
The populated optional migration preserves raw cancellation and never invents
missing original organization-version correlation for legacy effects.

`TestOrganizationGenuineLifecycleOperationConsumer` proves original-key archive
and fresh-proof restore after real signup, verification and password signin.
It checks warm/current denial, invitation cancellation, surviving membership,
original recovery, changed-input conflict, rollback, actual COMMIT-response loss,
same-key contention and current authority/session withdrawal. Its selected
request-admission callback grants no native owner or proof authority.

`TestOrganizationGenuineInvitationResendOperationConsumer` exercises original-key
resend through the published adapter: fixed recipient/role/deadline, predecessor
denial, encrypted successor delivery and acceptance, and reconstructed original
recovery after later resends and acceptance. It also covers current administrator
and recipient withdrawal (including inside delivery-status policy), rollback,
mapping-only/final COMMIT-response loss, immutable original expiry/refusal and
concurrent-key singleton effects before any recovery retry.
