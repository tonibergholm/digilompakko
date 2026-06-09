# Requirement Traceability Matrix

This matrix maps the EUDI capability areas (from the **ARF 2.x**, **HAIP 1.0**, and the underlying
OpenID4VC / IETF / ISO standards) to the concrete code and tests that implement them in this repo.
It is the artefact to hand an auditor or a contributor asking "where is requirement X?".

> Status: ✅ implemented (demo) · 🟡 partial · ⬜ not yet · ⛔ out of scope for a software reference
>
> The ARF expresses requirements as numbered items in its Annexes (e.g. topic-scoped IDs). Pinning
> each exact ARF requirement ID to a line of code is a living task tracked in `ROADMAP.md` Phase 4;
> this matrix maps by **capability**, citing the governing spec, so it stays accurate as ARF IDs
> are renumbered between iterations.

## Credential formats

| Capability | Spec | Code | Tests | Status |
|---|---|---|---|---|
| SD-JWT VC issuance (`dc+sd-jwt`) | IETF SD-JWT VC; HAIP §SD-JWT VC | `core/src/sd-jwt.ts` `issueSdJwtVc` | `test/sd-jwt.test.ts` | ✅ |
| Selective disclosure (salted-hash digests) | IETF SD-JWT | `core/src/sd-jwt.ts` | `test/sd-jwt.test.ts` | ✅ |
| mdoc / mDL (`mso_mdoc`, CBOR/COSE) | ISO/IEC 18013-5; HAIP §mdoc | `core/src/mdoc.ts` | `test/mdoc.test.ts` | ✅ (subset) |
| mdoc selective disclosure (MSO value digests) | ISO/IEC 18013-5 | `core/src/mdoc.ts` | `test/mdoc.test.ts` | ✅ |
| Format negotiation in issuer metadata | OpenID4VCI §Metadata | `apps/issuer` metadata | live | ✅ |

## Issuance (OpenID4VCI)

| Capability | Spec | Code | Tests | Status |
|---|---|---|---|---|
| Issuer metadata + JWKS | OpenID4VCI §Issuer Metadata | `apps/issuer` `/.well-known/openid-credential-issuer` | live | ✅ |
| Pre-authorized code flow | OpenID4VCI §Pre-Auth; HAIP | `apps/issuer` `/token` | live | ✅ |
| Authorization Code flow | OpenID4VCI §Auth Code | `apps/issuer` `/authorize`, `/token` | live | ✅ |
| Pushed Authorization Requests | RFC 9126 (PAR) | `apps/issuer` `/par` | live | ✅ |
| PKCE (S256) | RFC 7636; HAIP | `core/src/pkce.ts` | `test/phase3.test.ts` | ✅ |
| Holder Proof-of-Possession (key binding) | OpenID4VCI §Proof Types | wallet `fetchCredential`; issuer `/credential` | live | ✅ |

## Presentation (OpenID4VP)

| Capability | Spec | Code | Tests | Status |
|---|---|---|---|---|
| Authorization Request + `direct_post` | OpenID4VP | `apps/verifier` `/presentation/request` | live | 🟡 subset — plaintext `direct_post` only; HAIP requires encrypted `direct_post.jwt` (HIGH-4) |
| DCQL query | OpenID4VP §DCQL | `apps/verifier` `DCQL`; `core` `checkDcqlSatisfied` | `test/extras.test.ts` | ✅ enforced against response — format, `vct`/doctype, required claims validated (HIGH-3 fixed, PR [#23](https://github.com/tonibergholm/digilompakko/pull/23)) |
| `vp_token` verification | OpenID4VP; HAIP | `core/src/sd-jwt.ts` `verifyPresentation` | `test/sd-jwt.test.ts` | ✅ |
| Key Binding JWT (replay: nonce + aud) | IETF SD-JWT (KB-JWT) | `core/src/sd-jwt.ts`; `createPresentation` | `test/sd-jwt.test.ts` | ✅ nonce + aud checked; session atomically consumed after use (HIGH-2 fixed, PR [#22](https://github.com/tonibergholm/digilompakko/pull/22)) |
| mdoc DeviceAuth (nonce-bound) | ISO/IEC 18013-5 | `core/src/mdoc.ts` | `test/mdoc.test.ts` | ✅ (subset) |
| Signed request object (JAR) | RFC 9101; HAIP | `core/src/request-object.ts`; verifier `/jwks.json` | `test/extras.test.ts` | 🟡 JAR verified: signature + `alg`/`typ`/`exp`/`aud` (HIGH-1 fixed, PR [#21](https://github.com/tonibergholm/digilompakko/pull/21)); `x509_hash` binding absent (HAIP MUST — see §5a) |

## Trust, revocation & key management

| Capability | Spec | Code | Tests | Status |
|---|---|---|---|---|
| Issuer trust resolution (pluggable) | ARF §Trusted Lists | `core/src/trust.ts` | `test/status-list.test.ts` | ✅ (static) |
| Trusted Lists / Registrar client | ARF §Trust Model | — | — | 🟡 interface only |
| Token Status List revocation (SD-JWT VC) | IETF Token Status List | `core/src/status-list.ts`; issuer `/statuslist`, `/admin/revoke` | `test/status-list.test.ts` | ✅ |
| Token Status List revocation (mdoc, status in MSO) | IETF Token Status List | `core/src/mdoc.ts`; verifier mdoc path | `test/extras.test.ts` | ✅ |
| Credential expiry enforcement | SD-JWT / mdoc validity | `core/src/sd-jwt.ts`, `core/src/mdoc.ts` | live | ✅ |
| WSCD key-storage boundary | ARF §WSCD | `core/src/keystore.ts` | `test/phase3.test.ts` | ✅ (software) |
| Hardware-backed WSCD | ARF §WSCD / CC certification | — | — | ⬜ |

## Relying Party governance

| Capability | Spec | Code | Tests | Status |
|---|---|---|---|---|
| RP registration | ARF §RP Registration | `core/src/rp-registry.ts`; verifier `/rp/:id` | `test/phase3.test.ts` | ✅ |
| Attribute-entitlement (data minimisation) | ARF §RP access | `core/src/rp-registry.ts` `assertEntitled` | `test/phase3.test.ts` | ✅ |
| RP access certificates (X.509 + Trusted List) | ARF §RP access certs | — | — | ⬜ |

## Cryptography

| Capability | Spec | Code | Status |
|---|---|---|---|
| ES256 / P-256 only | HAIP §Crypto Suites | `core/src/crypto.ts`, all signers | ✅ enforced |
| No hand-rolled signature crypto | project policy | `jose` (JWS) + Node `crypto` (COSE raw) | ✅ |

## HAIP 1.0 Final — MUST-level controls (absent)

Controls mandated by HAIP 1.0 Final (24 Dec 2025) that are not yet implemented.
See `docs/COMPLIANCE.md` §5a for detail.

| HAIP MUST control | Status |
|---|---|
| FAPI 2.0 / DPoP sender-constrained access tokens | 🔴 absent |
| Wallet client authentication at PAR/token endpoints | 🔴 absent |
| Wallet attestation + key attestation | 🔴 absent |
| `x509_hash` verifier authentication in signed requests | 🔴 absent |
| Encrypted OpenID4VP responses (`direct_post.jwt`) | 🔴 absent |
| Ephemeral response-encryption keys | 🔴 absent |
| `trusted_authorities` DCQL support | 🔴 absent |

## Out of scope for a software reference (⛔)

- Proximity device retrieval (ISO 18013-5 BLE/NFC) and online (ISO 18013-7) — require mobile hardware.
- Common Criteria / eIDAS certification and CAB audit — external processes (see `CONFORMANCE.md`).
- Real PID issuance bound to a national eID / population register (DVV's domain).
