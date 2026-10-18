# Current-subject organization listing

Core and native `Service.ListOrganizations` implement the distinct read operation
`identity.organization.list`. Supply `ListOrganizationsRequest` with current
`Authentication`, explicit `Limit`, optional returned `Cursor` and correlation
ID. There is no target user, caller-selected tenant override or global active
organization selection. The existing `Repository.Read` interface is unchanged;
native `Repository` additionally implements `OrganizationListReader`.

`ListOrganizationsResult.Organizations` is an owned slice of safe current active
organization snapshots in ascending bytewise canonical-ID order. `Limit` is
1–200, matching the typed list catalog. Empty membership or entirely denied
visibility returns an empty successful page. A current active membership is
necessary but does not imply per-organization list permission.

The primary adapter uses the existing active `(tenant_id,user_id,organization_id)`
membership index and active organization join. Each invocation scans remaining
self-memberships after the cursor only up to the explicit `MaximumPerUser`
startup cap (1–1,000), with one bounded overflow detector. Exceeding the cap
fails closed rather than claiming EOF or returning a truncated visibility scan.
All reads and callbacks share the existing whole-call deadline. This does not
promise a performance budget beyond the configured bounds.

Only an explicit initial policy `Deny` at the configured revision omits an
organization. Unknown outcomes, revision mismatch, errors and cancellation
return no partial page. Captured allows are checked again, then the actual
session and exact organization/member/scoped authority snapshots are re-read
after callbacks. A late withdrawal denies the response, including withdrawal
affecting an earlier candidate. Revalidation never renews the original session
observation's exclusive freshness interval. Leaving/removal excludes that
membership; authorized readmission is visible under its new epochs.

Continuation is derived only from the last returned visible organization ID,
not a hidden candidate. The opaque versioned framing is bound to tenant,
authenticated subject and deployed policy, fits the catalog's 512-byte bound,
and is neither signed authority nor a retained snapshot. Do not decode or edit
it; changing scope invalidates it. A caller-crafted position cannot bypass
current authentication, membership or policy. Page size may change between
requests. Concurrent changes before the exclusive cursor require restarting;
changes during a response's admission checks fail closed.

No list call mutates membership, global password/session authority, active
selection, audit/outbox state or independent organization-owned credentials.
No migration or dependency change is required. HTTP, archive lifecycle,
dynamic roles and complete M22 qualification are not selected by this profile.
