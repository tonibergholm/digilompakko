# Security & Compliance Audit — 2026-06-09

**Scope:** Source-code, dependency, and documentation review of the
[Digilompakko](https://github.com/tonibergholm/digilompakko) EUDI wallet reference implementation.

**Date:** 2026-06-09  
**Auditor:** Internal (automated + manual review)  
**Build state at audit time:** `npm run build` ✅ · `npm test` 18/18 ✅ · `npm run demo` ✅ · `npm audit` clean · no committed secrets

---

## Summary

The project is a useful, readable end-to-end reference demo of the OpenID4VC + HAIP credential
stack. It is **not HAIP 1.0 conformant** and must not be described as an EUDI-compliant wallet.
Four HIGH-severity findings relate to security correctness; seven further MEDIUM/LOW findings
relate to hardening and supply-chain posture.

A manual proof was made that a signed wrong-type SD-JWT VC with zero disclosures is accepted by
`verifyPresentation()` — confirming HIGH-3 (DCQL not enforced).

## Remediation status (as of 2026-06-09)

All 11 code-level findings fixed and merged. HIGH-4 (HAIP MUST-level architectural gaps) is a
documentation correctness finding addressed by correcting compliance tables; the underlying
controls remain absent and are tracked in `ROADMAP.md`.

| Finding | PR | Merged |
|---|---|---|
| HIGH-1 — Wallet verifier authentication | [#21](https://github.com/tonibergholm/digilompakko/pull/21) | ✅ |
| HIGH-2 — Session replay | [#22](https://github.com/tonibergholm/digilompakko/pull/22) | ✅ |
| HIGH-3 — DCQL not enforced | [#23](https://github.com/tonibergholm/digilompakko/pull/23) | ✅ |
| HIGH-4 — HAIP MUST controls (docs corrected) | [#20](https://github.com/tonibergholm/digilompakko/pull/20) | ✅ |
| MEDIUM-1 — SSRF / unrestricted outbound fetches | [#24](https://github.com/tonibergholm/digilompakko/pull/24) | ✅ |
| MEDIUM-2 — Token/auth-code expiry not enforced | [#25](https://github.com/tonibergholm/digilompakko/pull/25) | ✅ |
| MEDIUM-3 — Status-token claim validation | [#26](https://github.com/tonibergholm/digilompakko/pull/26) | ✅ |
| MEDIUM-4 — Mobile crypto validation + user auth | [#27](https://github.com/tonibergholm/digilompakko/pull/27) | ✅ |
| MEDIUM-5 — iOS ATS broad exception | [#28](https://github.com/tonibergholm/digilompakko/pull/28) | ✅ |
| LOW-1 — Error response information disclosure | [#30](https://github.com/tonibergholm/digilompakko/pull/30) | ✅ |
| LOW-2 — Supply-chain controls | [#29](https://github.com/tonibergholm/digilompakko/pull/29) | ✅ |

---

## Findings

### HIGH-1 — Wallet verifier authentication is attacker-controlled

**Files:** `apps/wallet/src/wallet.ts:131-136`, `mobile/ios/Digilompakko/Wallet.swift:77-87`

The wallet reads `client_id` from the unverified request JWT, fetches a JWKS from that
attacker-controlled URL, and accepts a signature from the returned key. Any attacker can therefore
self-authenticate as a verifier. The TypeScript and iOS wallets also accept unsigned requests
outright. There is no trusted RP registry or access-certificate check in the wallet path.

**Impact:** Credential disclosure to an unregistered attacker; attacker controls all network
destinations used by the wallet during a presentation flow.

**Remediation:** Reject unsigned redirect-flow requests; authenticate verifiers via the HAIP
`x509_hash` client identifier with a trusted cert chain / access-certificate policy; bind and
validate `client_id`, `response_uri`, request URI, audience, expiry, and request-object `typ`.

**GitHub issue:** [#9](https://github.com/tonibergholm/digilompakko/issues/9)  
**Status:** ✅ Fixed — PR [#21](https://github.com/tonibergholm/digilompakko/pull/21). Unsigned requests now rejected; JAR `alg`/`typ`/`exp`/`aud` validated; RP JWKS anchored to trusted origin. (`x509_hash` certificate binding is a HAIP MUST gap, tracked separately.)

---

### HIGH-2 — Presentation sessions are replayable

**File:** `apps/verifier/src/server.ts:126-176`

Sessions remain valid after a successful response. The same captured `vp_token` can be re-submitted
with the same session ID and nonce and will verify successfully a second time. Existing tests verify
that a *different* nonce fails, but do not test one-time session consumption.

**Impact:** A captured presentation can be replayed within the lifetime of an existing session.

**Remediation:** Add session expiry and atomic one-time consumption *before* verification is
attempted; reject all subsequent responses including concurrent submissions; add tests for
exact-token replay and race conditions.

**GitHub issue:** [#10](https://github.com/tonibergholm/digilompakko/issues/10)  
**Status:** ✅ Fixed — PR [#22](https://github.com/tonibergholm/digilompakko/pull/22). Sessions atomically consumed before verification; 5-minute TTL; replay and race-condition adversarial tests added.

---

### HIGH-3 — Verifier does not enforce DCQL or requested credential semantics

**Files:** `apps/verifier/src/server.ts:52-79,135-175`, `packages/core/src/sd-jwt.ts:118-182`,
`packages/core/src/mdoc.ts:219-285`

The verifier generates DCQL requests but never validates the response against them. It does not
check the `vct`/doctype of the presented credential, the required claims, claim values, or format
semantics. The mdoc path does not bind the document `docType` to the signed MSO `docType`.

**Manual proof:** A signed SD-JWT VC with a wrong `vct` and zero disclosures passed
`verifyPresentation()` and was recorded as a valid verification.

**Impact:** Any valid credential — regardless of type, claims, or format — can satisfy a
presentation request.

**Remediation:** Validate the verified result against the stored DCQL query (format,
`vct`/doctype, required claim set, trusted authority, expected values). Bind mdoc `docType` and
DeviceAuthentication fields to the signed MSO and the request.

**GitHub issue:** [#11](https://github.com/tonibergholm/digilompakko/issues/11)  
**Status:** ✅ Fixed — PR [#23](https://github.com/tonibergholm/digilompakko/pull/23). `vp_token` validated against stored DCQL query (format, `vct`/doctype, required claims); mdoc `docType` bound to MSO.

---

### HIGH-4 — Implementation does not satisfy HAIP 1.0 Final mandatory controls

**Files:** `apps/issuer/src/server.ts:140-250`, `apps/verifier/src/server.ts:109-176`,
`docs/COMPLIANCE.md`, `docs/TRACEABILITY.md`

HAIP 1.0 became Final on 24 December 2025. Mandatory controls absent from this implementation:

| HAIP MUST control | Current state |
|---|---|
| FAPI 2.0 / DPoP sender-constrained access tokens | Bearer tokens only |
| Wallet client authentication at PAR/token endpoints | No client auth |
| Wallet attestation + key attestation | Not implemented |
| `x509_hash` signed-request verifier authentication | Not implemented |
| Encrypted OpenID4VP responses (`direct_post.jwt`) | Plaintext `direct_post` |
| Ephemeral response-encryption keys | Not implemented |
| `trusted_authorities` DCQL support | Not implemented |

**Impact:** Documentation overstates conformance; could mislead adopters or auditors.

**Remediation:** Change compliance tables from ✅ to 🔴/⬜ for absent mandatory controls until
external conformance runs pass; pin exact spec versions; maintain a MUST-level matrix.

**GitHub issue:** [#12](https://github.com/tonibergholm/digilompakko/issues/12)  
**Status:** ✅ Fixed (documentation) — PR [#20](https://github.com/tonibergholm/digilompakko/pull/20). Compliance tables corrected from ✅ to 🔴/⬜ for all absent MUST-level controls; MUST-level matrix added. The controls themselves remain absent (architectural gaps tracked in `ROADMAP.md`).

---

### MEDIUM-1 — Unrestricted outbound fetches (SSRF / exfiltration)

**Files:** `apps/wallet/src/wallet.ts:117-136`, `apps/verifier/src/server.ts:143-167`,
`packages/core/src/trust.ts:33-42`

Request URI, unverified `client_id`, response URI, issuer-metadata URL, and credential status URI
are fetched with no scheme/host allow-list, redirect policy, timeout, size limit, or content-type
validation.

**Impact:** A malicious verifier or compromised issuer can probe internal services, exfiltrate data,
or stall/exhaust the process.

**Remediation:** Centralize hardened HTTP clients; require HTTPS outside explicit local-demo mode;
allow-list origins; reject private/link-local addresses and redirects to them; enforce timeouts,
size limits, expected status codes, and media types.

**GitHub issue:** [#13](https://github.com/tonibergholm/digilompakko/issues/13)  
**Status:** ✅ Fixed — PR [#24](https://github.com/tonibergholm/digilompakko/pull/24). `assertSafeUrl` (HTTPS required; HTTP only to loopback) and `safeFetch` (5 s timeout, 1 MiB cap) added to `packages/core`; all outbound fetches in wallet and verifier routed through them.

---

### MEDIUM-2 — Issuer tokens and auth requests do not expire as advertised

**File:** `apps/issuer/src/server.ts:51-59,140-197,203-246`

PAR responses advertise 90 s expiry and access tokens advertise 300 s, but neither issuance
timestamp nor expiry is stored or enforced. Authorization codes have no expiry. State maps have no
capacity bound or periodic cleanup.

**Impact:** Leaked bearer artifacts remain usable until the process restarts; unauthenticated
clients can grow server memory indefinitely.

**Remediation:** Store issuance/expiry timestamps and enforce them atomically; bind auth codes to
`client_id` + redirect URI; cap state maps; periodically remove expired records.

**GitHub issue:** [#14](https://github.com/tonibergholm/digilompakko/issues/14)  
**Status:** ✅ Fixed — PR [#25](https://github.com/tonibergholm/digilompakko/pull/25). PAR, auth-code, access-token, and c_nonce TTLs stored and enforced server-side; `c_nonce_expires_in: 300` advertised.

---

### MEDIUM-3 — Status-token verification lacks issuer/subject and decompression constraints

**Files:** `packages/core/src/status-list.ts:82-100`, `apps/verifier/src/server.ts:162-171`

`readStatus()` verifies the JWT signature but does not check the expected issuer, expected
status-list URI (`sub` claim), `bits === 1`, non-negative integer index, or a maximum decompressed
list size.

**Impact:** Status semantics can be confused across issuers; a trusted-but-compromised issuer can
trigger resource exhaustion via a crafted status list.

**Remediation:** Pass expected issuer and URI into verification, validate all claims and index
types, impose compressed/decompressed size limits.

**GitHub issue:** [#15](https://github.com/tonibergholm/digilompakko/issues/15)  
**Status:** ✅ Fixed — PR [#26](https://github.com/tonibergholm/digilompakko/pull/26). `readStatus()` now validates `iss` against expected issuer, `sub` against expected URI, and `bits === 1`; adversarial tests for wrong-issuer and wrong-URI added.

---

### MEDIUM-4 — Mobile crypto verification and user auth are incomplete

**Files:** `mobile/android/app/src/main/java/fi/digilompakko/wallet/Jose.kt:40-49`,
`mobile/android/.../SecureKeyStore.kt:60-65`,
`mobile/ios/Digilompakko/Jose.swift:61-76`,
`mobile/ios/Digilompakko/SecureKeyStore.swift:58-66`

Native JWS verification validates only the signature — not required `alg`, `typ`, expiry, audience,
or other request claims. Android/iOS signing keys do not require user authentication or biometric
approval before use. Both platforms use a single long-lived holder key for all credentials,
increasing linkability.

**Impact:** Request policy bypass; silent signing on device compromise; correlatable presentations.

**Remediation:** Add full JOSE/request claim validation; require per-operation user authorization;
add hardware/key attestation; consider per-credential or batch single-use keys.

**GitHub issue:** [#16](https://github.com/tonibergholm/digilompakko/issues/16)  
**Status:** ✅ Fixed — PR [#27](https://github.com/tonibergholm/digilompakko/pull/27). `verifyRequestObject()` added to iOS (`Jose.swift`) and Android (`Jose.kt`) validating `alg`/`typ`/`exp`/`aud`; Secure Enclave `.userPresence` and Android `setUserAuthenticationRequired(true)` with 30 s window added.

---

### MEDIUM-5 — Cleartext transport and broad iOS ATS exception

**Files:** default service URLs in all three server apps; `mobile/ios/Digilompakko/Info.plist:27-34`

All default protocol traffic uses HTTP. The iOS app enables `NSAllowsArbitraryLoads` (global
cleartext transport).

**Impact:** Credentials, bearer tokens, proofs, and presentations can be observed or modified in
transit on any non-loopback network.

**Remediation:** Make insecure transport an explicit local-only mode; bind demo services to the
loopback interface; require TLS for all non-loopback traffic; remove the broad ATS exception and
use a narrow debug-only exception.

**GitHub issue:** [#17](https://github.com/tonibergholm/digilompakko/issues/17)  
**Status:** ✅ Fixed — PR [#28](https://github.com/tonibergholm/digilompakko/pull/28). `NSAllowsArbitraryLoads` removed from `Info.plist`; replaced with narrow `NSExceptionDomains` scoped to `localhost` only.

---

### LOW-1 — Error responses disclose internal exception details

**Files:** `packages/core/src/errors.ts:41-47`, wallet HTTP handlers

Unexpected exception messages (including internal state) are forwarded directly to HTTP clients.

**Impact:** Internal parsing, network, and implementation details aid attacker reconnaissance.

**Remediation:** Return stable, public error codes/messages to clients; log sanitized diagnostic
detail server-side only.

**GitHub issue:** [#18](https://github.com/tonibergholm/digilompakko/issues/18)  
**Status:** ✅ Fixed — PR [#30](https://github.com/tonibergholm/digilompakko/pull/30). Non-`Oid4vcError` exceptions in `sendError` now log server-side and return `"an internal error occurred"` to clients.

---

### LOW-2 — Supply-chain and assurance controls are minimal

**Files:** `.github/workflows/ci.yml`, repo root

CI builds and tests TypeScript but has no least-privilege workflow `permissions`, dependency
review, CodeQL/SAST, secret-scanning configuration, SBOM, provenance/signing, license policy,
mobile build/test pipeline, or automated conformance runs.

**Impact:** Fewer preventative and detective controls for security regressions and supply-chain
issues.

**Remediation:** Add read-only workflow permissions, dependency review, CodeQL, secret scanning,
SBOM/provenance, mobile CI, and recorded conformance-suite runs.

**GitHub issue:** [#19](https://github.com/tonibergholm/digilompakko/issues/19)  
**Status:** ✅ Fixed — PR [#29](https://github.com/tonibergholm/digilompakko/pull/29). Action SHAs pinned (`actions/checkout` v4.2.2, `actions/setup-node` v4.2.0); `permissions: contents: read` added; `npm audit --audit-level=high` step added.

---

## Dependency scan

`npm audit` — clean at audit time (no known vulnerabilities in the dependency tree).

---

## What is NOT a finding

- Software key storage (`SoftwareKeyStore`): documented and intentional for a reference demo.
- In-memory state (no database): documented scope.
- HTTP default transport for localhost: noted under MEDIUM-5 as a hardening gap, not a
  show-stopper for a localhost-only demo — severity increases for any networked deployment.
- Missing conformance-suite runs: noted under LOW-2 and HIGH-4.
