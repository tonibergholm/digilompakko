# Digilompakko — Spec Compliance & Architecture Plan

> An open-source, EUDI-**aligned** digital identity wallet **reference demo** (issuer + wallet +
> verifier), built *toward* the EU **Architecture and Reference Framework (ARF) 2.x** and the
> **OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0 Final** (24 December 2025).
> It is **not** an EUDI-compliant, certified, or HAIP-conformant wallet.

This document maps the regulatory and technical requirements to a concrete architecture so
that anyone can verify *why* each component exists and *which spec clause* it satisfies. Where
this repo demonstrates a primitive but does **not** yet meet the spec's MUST-level bar, that is
stated explicitly — see §5a (HAIP MUST-level matrix) and §6 (gap to certification).

> ⚠️ **Security audit (2026-06-09).** An internal source-and-repository audit
> ([`docs/SECURITY_AUDIT_2026-06-09.md`](./SECURITY_AUDIT_2026-06-09.md)) found this
> implementation is **not HAIP 1.0 conformant** and must not be described as an EUDI wallet.
> The highest-risk findings are: (HIGH-1) wallet verifier authentication is attacker-controlled
> and unsigned requests are accepted; (HIGH-2) presentation sessions are replayable; (HIGH-3)
> the verifier generates a DCQL query but does **not enforce it** against the presented
> credential; (HIGH-4) mandatory HAIP controls (DPoP, wallet/key attestations, `x509_hash`
> request authentication, encrypted `direct_post.jwt` responses, `trusted_authorities`) are
> absent. Status markers in the tables below have been corrected to reflect this; do not read
> a "✅ demo" marker as "spec-conformant".

---

## 1. What "compliant" means here

The Finnish wallet (DVV's *Suomi.fi Wallet*) and every other EU member-state wallet must satisfy
the **amended eIDAS Regulation (EU) 2024/1183** through a layered set of specifications. There is
no single "the spec" — compliance is a *stack*:

| Layer | Specification | Role in this project |
|-------|---------------|----------------------|
| Law | **eIDAS 2.0 — Reg. (EU) 2024/1183** + implementing acts | The legal mandate. Defines wallet, PID, attestations, trust model. |
| Framework | **EU Architecture & Reference Framework (ARF) 2.x** | High-level architecture, roles, requirements catalogue (we cite requirement IDs). |
| Interop profile | **OpenID4VC HAIP 1.0 Final** (24 Dec 2025) | Pins the optional knobs of the OpenID4VC specs to one secure, interoperable subset. This repo implements a **partial subset**; several MUST-level controls are absent (§5a). |
| Issuance | **OpenID for Verifiable Credential Issuance (OpenID4VCI) 1.0** | How the issuer hands credentials to the wallet. |
| Presentation | **OpenID for Verifiable Presentations (OpenID4VP) 1.0** | How a verifier requests and the wallet presents credentials. |
| Credential format A | **IETF SD-JWT VC** (`dc+sd-jwt`) | Selective-disclosure JSON credential format. **Primary format in this demo.** |
| Credential format B | **ISO/IEC 18013-5 mdoc / mDL** (`mso_mdoc`) | Binary CBOR/COSE format, esp. mobile driving licence. **Implemented (subset).** |
| Query | **DCQL** (Digital Credentials Query Language) | How a verifier expresses *what* it wants. |
| Status | **IETF Token Status List** | Credential revocation/suspension. **Implemented (SD-JWT VC + mdoc).** |
| Request auth | **JAR (RFC 9101)** | Signed OpenID4VP request objects. **Implemented.** |
| Crypto | **ES256 / P-256** mandated by HAIP | Signing + holder key binding. |

> **Scope of this repo:** a faithful, readable **end-to-end demo** of issue → store → present →
> verify over OpenID4VCI/VP with HAIP crypto, for **both** credential formats (SD-JWT VC and ISO
> 18013-5 mdoc/mDL), including selective disclosure, holder/device binding, Token Status List
> revocation, a WSCD key-storage boundary, Authorization Code + PAR + PKCE issuance, RP registration,
> and signed request objects. It is a learning and conformance-testing reference, **not** a certified
> production wallet. See §6 for the gap to certification.

---

## 2. ARF roles → our components

The ARF defines a set of ecosystem roles. This demo implements the three that close the loop:

```
            ┌─────────────┐   OpenID4VCI 1.0    ┌──────────────┐
            │   ISSUER    │ ───────────────────▶│    WALLET    │
            │ (PID/EAA    │   credential offer  │  (Holder /   │
            │  provider)  │   + SD-JWT VC       │  Wallet Unit)│
            └─────────────┘                     └──────┬───────┘
                                                       │
                                                       │ OpenID4VP 1.0
                                                       │ (vp_token: SD-JWT VC + KB-JWT)
                                                       ▼
                                                ┌──────────────┐
                                                │   VERIFIER   │
                                                │  (Relying    │
                                                │   Party)     │
                                                └──────────────┘
```

| ARF role | Repo component | Folder |
|----------|----------------|--------|
| PID Provider / Attestation Provider | **Issuer** service (OpenID4VCI) | `apps/issuer` |
| Wallet Unit (holder) | **Wallet** service + minimal web UI | `apps/wallet` |
| Relying Party | **Verifier** service (OpenID4VP) | `apps/verifier` |
| Shared crypto, SD-JWT VC, trust utils | **Core** library | `packages/core` |

Out of scope (documented in `ROADMAP.md`): Wallet Provider backend, PID issuance with a real eID,
real Trusted Lists / Registrar and RP access certificates, hardware-backed WSCD, and proximity
flows (BLE/NFC, ISO 18013-7). The verifier also handles the **mdoc** format and signs its requests
(JAR); both are exercised end-to-end.

---

## 3. The end-to-end flow this demo implements

**Issuance (OpenID4VCI 1.0, pre-authorized code flow — HAIP recommended for wallets):**

1. Issuer publishes metadata at `/.well-known/openid-credential-issuer`.
2. Issuer creates a **Credential Offer** (QR/deeplink) for a `PersonIdentificationData` (PID) credential.
3. Wallet redeems the **pre-authorized code** at the token endpoint → access token + `c_nonce`.
4. Wallet generates a **holder key pair (P-256)** and a **proof of possession JWT** bound to `c_nonce`.
5. Wallet calls `/credential`; issuer returns an **SD-JWT VC** with selectively-disclosable claims
   and the holder's public key as the confirmation (`cnf`) key — i.e. **holder binding**.

**Presentation (OpenID4VP 1.0 + HAIP):**

6. Verifier creates an **Authorization Request** containing a **DCQL query** ("give me `given_name`,
   `family_name`, and proof `age_over_18 = true`") and a `nonce`.
7. Wallet matches the query, lets the user **consent**, and builds a presentation:
   the issued SD-JWT + only the **chosen disclosures** + a **Key Binding JWT (KB-JWT)** signed by the
   holder key over the verifier's `nonce` + `aud`.
8. Verifier validates: issuer signature, disclosure digests, `cnf`/KB-JWT holder binding, `nonce`,
   `aud`, and expiry. It learns *only* the disclosed claims — selective disclosure in action.

This single path exercises every core compliance primitive: issuer trust, selective disclosure,
holder binding, replay protection, and minimal disclosure.

---

## 4. Why these technology choices

- **TypeScript / Node monorepo (npm workspaces).** The largest open-source OpenID4VC ecosystem
  lives in TS/JS (Sphereon, `@sd-jwt/*`, `jose`, `oid4vc` libraries), so it is the fastest route to
  an interoperable, readable demo. The EU *reference* implementations are Kotlin/Swift/Python; this
  repo is a complementary, approachable TS reference. (Stack is swappable per component.)
- **`jose`** for all JWS/JWT signing & verification — audited, standards-correct, no hand-rolled crypto.
- **SD-JWT VC first, mdoc alongside.** HAIP requires SD-JWT VC support of all parties; the ISO
  18013-5 mdoc/mDL format is implemented too and exercised end-to-end.
- **ES256 / P-256 everywhere**, per HAIP §"Cryptographic Suites".
- **Express** services with OpenAPI-style routes mirroring the spec endpoints, so each HTTP route maps
  1:1 to a clause you can cite.

---

## 5. Compliance traceability (what to point an auditor at)

| Requirement | Where it lives | Status |
|-------------|----------------|--------|
| SD-JWT VC issuance (`dc+sd-jwt`) | `packages/core/src/sd-jwt.ts` `issueSdJwtVc()` | ✅ demo |
| Selective disclosure (salted-hash digests) | `packages/core/src/sd-jwt.ts` | ✅ demo |
| Holder binding via `cnf` + KB-JWT | `core` `createPresentation()` / `verifyPresentation()` | ✅ demo |
| OpenID4VCI metadata + offer + token + credential | `apps/issuer` | 🟡 demo (pre-auth + Auth Code/PAR/PKCE; advertised token/PAR/code expiry **not yet enforced** — audit MEDIUM-2) |
| OpenID4VP request with DCQL + nonce/aud | `apps/verifier` | 🟡 demo — request is built, but the DCQL query is **not enforced** against the response (audit HIGH-3) and sessions are **replayable** (audit HIGH-2) |
| Verifier (RP) authentication in the wallet | `apps/wallet` | 🔴 **not safe** — `client_id`/JWKS are attacker-controlled and unsigned requests are accepted (audit HIGH-1) |
| ES256 / P-256 only | `packages/core/src/crypto.ts` | ✅ enforced |
| Token Status List revocation (`statuslist+jwt`) | `core/src/status-list.ts`, issuer `/statuslist` + `/admin/revoke`, verifier check | ✅ demo |
| Pluggable trust resolution (allow-list today) | `core/src/trust.ts` `StaticTrustResolver` | ✅ demo |
| Structured error model | `core/src/errors.ts` `Oid4vcError` | ✅ demo |
| Credential expiry enforcement | `core/src/sd-jwt.ts` (`exp`) | ✅ demo |
| ISO 18013-5 mdoc / mDL (`mso_mdoc`, CBOR/COSE_Sign1) | `core/src/mdoc.ts`; issuer advertises `mso_mdoc` | ✅ demo (subset) |
| mdoc device binding (deviceAuth over nonce) | `core/src/mdoc.ts` | ✅ demo |
| mdoc revocation (status in MSO → Token Status List) | `core/src/mdoc.ts`; issuer + verifier | ✅ demo |
| OpenID4VP signed request objects (JAR, RFC 9101) | `core/src/request-object.ts`; verifier `/jwks.json` | ✅ demo |
| WSCD key-storage boundary (keys never exported) | `core/src/keystore.ts` (`WalletKeyStore`, `JwsSigner`) | ✅ demo (software) |
| Authorization Code + PAR + PKCE issuance | issuer `/par`, `/authorize`, `/token`; `core/src/pkce.ts` | ✅ demo |
| Relying Party registration + entitlement gate | `core/src/rp-registry.ts`; verifier `/rp/:id` | ✅ demo |
| Real Trusted Lists / Registrar | `TrustResolver` interface ready; static for now | 🟡 interface only |
| Hardware-backed WSCD (secure element / TEE / HSM) | — | ⬜ roadmap (software keystore today) |

---

## 5a. HAIP 1.0 Final — MUST-level controls matrix

HAIP 1.0 Final (24 December 2025) mandates several controls that this demo does **not** implement.
Until a full external conformance run passes, these must be listed as absent:

| HAIP MUST-level control | Ref | Status | Notes |
|---|---|---|---|
| FAPI 2.0 sender-constrained access tokens (DPoP) | HAIP §8.2 | 🔴 absent | Bearer tokens used; DPoP not implemented |
| Wallet client authentication at PAR/token endpoints | HAIP §8.3 | 🔴 absent | No `client_assertion` / attestation-based auth |
| Wallet attestation (`wallet_attestation`) | HAIP §8.4 | 🔴 absent | Wallet identity is unverified |
| Key attestation (WSCD binding) | HAIP §8.4 | 🔴 absent | Software key, no hardware attestation |
| `x509_hash` verifier authentication in signed requests | HAIP §8.5 | 🔴 absent | Verifier JWKS self-published; `client_id` unverified (HIGH-1) |
| Encrypted OpenID4VP response (`direct_post.jwt`) | HAIP §8.6 | 🔴 absent | Plaintext `direct_post` used instead |
| Ephemeral response-encryption keys | HAIP §8.6 | 🔴 absent | No JARM encryption |
| `trusted_authorities` in DCQL | HAIP §8.7 | 🔴 absent | DCQL does not include trusted-authority constraints |

> After the HIGH-1, HIGH-2, and HIGH-3 code fixes are merged, the corresponding rows in §5 and
> this table will be updated. The HAIP MUST-level controls above require additive engineering work
> (DPoP, wallet/key attestations, encrypted responses) that is tracked in `ROADMAP.md`.

---

## 6. Gap to real certification (be honest about this)

A production EUDI wallet additionally requires, and this demo deliberately does **not** yet provide:

1. **Certified secure key storage** (WSCD — secure element / TEE / HSM). The key-storage *boundary*
   is abstracted (`core/src/keystore.ts`: keys never leave the store, signing happens inside it),
   but the demo's `SoftwareKeyStore` holds keys in memory. A hardware-backed implementation plugs
   in behind the same `WalletKeyStore` interface.
2. **Real PID issuance** tied to a national eID and the Population Information System (DVV's domain).
3. **Trust infrastructure**: real Trusted Lists, the EU Registrar, and RP **access certificates**
   (RP registration itself is modelled in `core/src/rp-registry.ts`; the certs and lists are not).
4. **Credential lifecycle** management — refresh / re-issuance (revocation via the Token Status List
   is implemented for both SD-JWT VC and mdoc).
5. **Proximity presentation** (BLE/NFC device retrieval, ISO 18013-7 for online). The `mso_mdoc`
   credential format itself is implemented (`core/src/mdoc.ts`), but as a **subset**: the
   SessionTranscript is simplified to bind audience+nonce (not the full 18013-5 device-engagement
   transcript), only `deviceSignature` (not `deviceMac`) is supported, and there is no
   over-the-wire device retrieval. These are documented simplifications, not silent gaps.
6. **Formal conformance testing** against the EU Launchpad / OpenID conformance suites and a CAB audit.

The architecture is structured so each of these is an additive module, not a rewrite. See `ROADMAP.md`.

**Correctness bugs (security findings — must be fixed before any production use):**

7. **Verifier authentication absent (HIGH-1):** The wallet accepts unsigned presentation requests
   and authenticates the verifier's JWKS from an attacker-controlled URL. This is a security bug,
   not a roadmap item. Fix tracked in issue [#9](https://github.com/tonibergholm/digilompakko/issues/9) / branch `fix/verifier-auth`.
8. **Session replay (HIGH-2):** Presentation sessions are not consumed after a successful
   verification — the same captured `vp_token` can be re-submitted. Fix tracked in issue
   [#10](https://github.com/tonibergholm/digilompakko/issues/10) / branch `fix/presentation-replay`.
9. **DCQL not enforced (HIGH-3):** The verifier generates a DCQL query but accepts any valid
   credential regardless of type, requested claims, or format semantics. Fix tracked in issue
   [#11](https://github.com/tonibergholm/digilompakko/issues/11) / branch `fix/enforce-dcql`.

---

## 7. Licensing

**Apache-2.0** (matches the EU reference implementations and is permissive for public-sector reuse).
EUPL-1.2 is a documented alternative if alignment with EU institutional licensing is preferred.

---

## 8. Authoritative references

- eIDAS 2.0 — Regulation (EU) 2024/1183
- EU ARF: https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/
- HAIP 1.0 Final (24 Dec 2025): https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html
- OpenID4VCI 1.0: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- OpenID4VP 1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- IETF SD-JWT VC: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
- EU reference implementations: https://github.com/eu-digital-identity-wallet
- EUDI Dev Hub: https://eu-digital-identity-wallet.github.io/Build/
