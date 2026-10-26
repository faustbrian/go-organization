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

`TestOrganizationGenuineOwnerTransferOperationConsumer` uses the public signup,
captured verification, password-signin and signed action-proof graph for an
original-key owner transfer into an existing member. It checks both role and
scoped-authority versions, the former owner's fresh-session original recovery,
changed-intent and last-owner denial, real mapping/domain COMMIT-response loss
without automatic execution, and actual source logout without revoking the
independent new owner. It consumes the published adapter, not local replacements.

`TestOrganizationGenuineSlugAvailabilityConsumer` uses signup-issued sessions
for a nonmember's advisory free/taken read around an actual owner create. It
proves tenant mismatch and native public signout denial without withdrawing an
independent owner's session; availability neither grants discovery/membership
nor reserves the candidate. No application store or authentication is replaced.

These consumers prove their selected existing native profiles, not full M22,
external lifecycle cascades or a stable organization release. See the
[native adoption and security notes](../README.md).

`TestOrganizationGenuineCreateTeamOperationConsumer` uses real signup,
verification and password sessions to create one empty team with a chosen
canonical ID through the public original-key operation. It covers original and
fresh-session/reconstructed recovery, changed intent, current-manager/tenant
denial, real quotas, rollback, mapping/domain COMMIT-response loss, contention
and actual SignOut. It configures the actual native owners with a two-team quota;
no credential rows, private authority, alternate journal or local replacement
substitutes for the public workflow. Team membership and lifecycle remain
separate profiles.

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

`TestOrganizationGenuineInvitationExpireOperationConsumer` proves natural-repeat
manager expiry after actual signup, verification and password signin. It covers
registered original reasons/versions, legacy NULL history, predecessor proof
denial, reconstructed/fresh-session original recovery, changed-intent and current
authority denials, atomic audit/outbox rollback, COMMIT-response loss and competing
expiry/acceptance. The optional migration never invents legacy correlation and
expiry does not advance membership or organization authority.

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

## Natural self-leave consumer

`TestOrganizationGenuineSelfLeaveOperationConsumer` consumes public root/native
modules without replacements. It runs real signup, captured verification and
password signin, then self-leave, original natural repeat and recovery through
a fresh native facade and fresh signin. It checks scoped-read withdrawal,
unchanged legacy recovery denial, readmission conflict, explicit history-only
recovery, last-owner protection and actual session signout denial. The native
lookup is installed in an independent migration namespace, not an application
receipt store. Use the existing disposable loopback PostgreSQL setup above and
select this test with `-tags=integration -race`.
