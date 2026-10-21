# Organization-owned domain evidence

This additive profile permits one externally observed proof per immutable
requested claim, followed by optional terminal revocation. Organization owns
the only proof type, proof versions, primary reads and command outcomes.
Reservations remain requested/withdrawn custody, not proof. SSO routing,
challenge issuance, DNS/HTTPS protocol adapters, renewal and takeover are not
implemented by this profile; this is not full SSO or organization qualification.

## Configuration and public path

1. Install `DomainEvidenceMigrationSource` after `DomainClaimMigrationSource`.
   Existing migration bytes are unchanged. The forward transaction adds proof
   history and terminal retirement of claim proof authority when its organization
   leaves active state. Requested/withdrawn identities and versions survive.
2. Set the same immutable `DomainConfig.EvidenceMaximumAge` in core/contributor
   configuration. Zero keeps reservation-only behavior. Its allowed 15-minute
   to 48-hour range follows `sso.domain_proof.ttl` in the identity reference
   configuration; an observer may return a shorter expiry. Original observation
   time, never preparation, execution, copying or recovery time, starts this age.
3. Configure `ContributorConfig.DomainEvidence` with `NewDomainEvidenceSource`,
   an explicitly trusted bounded observer and a secret 32-byte admission key.
   The observer must verify the exact scope-bound external challenge, not trust
   a caller's Boolean assertion. Its response contains no challenge or bearer.
   DNS TXT and HTTPS are method identifiers, not interoperability claims; the
   reference SSO profile selects DNS TXT only. Keep the admission key stable
   while prepared commands may execute. Never log/export the source or key.
   Application policy must explicitly permit `ApplyDomainProof` and
   `RevokeDomainProof` in the selected organization scope; an owner role does
   not replace that independent authorization decision.
4. Use `postgres.Service.DomainEvidence(authentication, canonicalClientIP)` to
   obtain an invocation-scoped authenticated facade. Call `Prepare` once with
   the exact requested claim/version and organization version. The selected
   observer executes once outside locks. Preparation retains one immutable
   native command/counter plan; a second preparation on that facade conflicts.
5. Save the safe `Recovery{Binding: command.Command().Input().Binding}` and keep
   the opaque command for `ApplyDomainEvidence`. Core and native services check
   current session/member/org/policy; native final admission rechecks original
   proof expiry at primary time after lock waits. Audit actions are exactly
   `identity.organization.verify_domain` and `identity.organization.revoke_domain`.
6. A committed result returns the original authoritative `Proof`. Convert it to
   `DomainProofKey` and call `GetDomainProof` for current acceptance. Every scope,
   method, version, original time, exclusive expiry and revocation dimension
   must match. Current proof reads deny expired, withdrawn, revoked or retired
   claims and inactive organizations. The authenticated facade also denies
   removed/demoted members and revoked sessions. Repository reads are the trusted
   primary service-to-service port, not human authentication.

## Exact recovery and terminal states

`DomainEvidenceTransition` exposes only `ApplyDomainEvidence` and
`RecoverDomainEvidence(ctx, commandID)`. To recover in a new process/session,
bind the saved `Recovery` as the optional third `Service.DomainEvidence` argument.
That metadata confers no access: current authentication must match the original
actor and tenant, and current organization/membership/action policy is checked.
It also permits exact recovery of not-committed/unknown outcomes without a proof
row. A facade without its own prepared command or saved exact scope rejects
recovery; a bare command ID never permits a global outcome/proof lookup.

An authorized committed recovery returns the identical original proof, including
after later proof expiry, withdrawal, revocation or restoration with retired
proof. Apply/retry still requires the original session and proof admission to be
valid; use recovery, not another Apply, after those original deadlines expire.
Inactive organizations still deny authenticated disclosure.
A historical committed result is not current routing authority. Unknown results
release no proof; recover the original command instead of observing again or
allocating a new command ID. Changed intent under one command ID conflicts.
The existing identity coordinator remains the sole journal, reservation and
transaction owner. Proof, organization epoch, participant effect, protected audit
and lifecycle outbox commit or roll back together.

`PrepareRevocation` requires exact current version-one proof and current
owner/admin authority; it does not call the observer. The committed version-two
proof retains the original method/times and is terminal. Another observation
cannot overwrite or renew that claim's proof. Withdrawal and archive retire
current authority; restore never revives pre-archive evidence. A later proof
requires withdrawing the old reservation and establishing a new immutable claim.

The migration adds one indexed tenant/org-scoped claim update to archive,
bounded by `MaximumClaims` for native claims. Its trigger covers old/new writers
without external callbacks; organization-before-claim locking matches native
mutation order. Migration/backfill may lock existing claim rows and must run
before enabling the profile. No production migration or scale budget is claimed.
