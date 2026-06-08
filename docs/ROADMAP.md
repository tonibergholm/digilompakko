# Roadmap

Status legend: ✅ done in demo · 🟡 partial · ⬜ planned

## Phase 0 — End-to-end SD-JWT VC happy path (this release)
- ✅ Monorepo, shared `core` library, three services
- ✅ P-256 key generation (ES256)
- ✅ SD-JWT VC issuance with selective disclosure + holder binding (`cnf`)
- ✅ OpenID4VCI pre-authorized code flow (offer → token → credential)
- ✅ OpenID4VP request with DCQL, nonce/aud replay protection
- ✅ Key Binding JWT (KB-JWT) creation & verification
- ✅ Minimal wallet web UI to drive the flow

## Phase 1 — Trust & lifecycle
- ✅ Token Status List revocation (issuer publishes signed `statuslist+jwt`, verifier checks)
- ✅ Pluggable trust resolver (`TrustResolver`) with a static Trusted List (`StaticTrustResolver`)
- ✅ Structured error model (`Oid4vcError`) per OpenID4VC/OAuth error registry
- ✅ Credential expiry enforced at verification (`exp`)
- 🟡 Credential refresh / re-issuance (expiry enforced; automated refresh still TODO)
- ⬜ Real Trusted List client (replace the static allow-list)

## Phase 2 — Second credential format
- ✅ ISO/IEC 18013-5 mdoc / mDL issuance & verification (`mso_mdoc`), subset
- ✅ CBOR/COSE_Sign1 support in `core` (`mdoc.ts`), ES256 device binding
- ✅ Format negotiation in issuer metadata (advertises `dc+sd-jwt` and `mso_mdoc`)
- 🟡 mdoc over OpenID4VCI/VP HTTP wire (core + headless demo done; full HTTP wiring TODO)
- ⬜ Full 18013-5 SessionTranscript + `deviceMac` variant

## Phase 3 — Real-world hardening
- ✅ WSCD key-storage abstraction (`WalletKeyStore`/`SoftwareKeyStore`, `JwsSigner`) — private keys
  never leave the store; credential APIs sign via the keystore
- ✅ Authorization Code flow + PAR (RFC 9126) + PKCE (RFC 7636), alongside pre-auth
- ✅ Relying Party registration + attribute-entitlement gate (`RelyingPartyRegistry`)
- 🟡 Access certificates (X.509 + Trusted List) for RPs — registry models the gate; certs are future
- ⬜ Hardware-backed WSCD implementation (secure element / TEE / HSM)
- ⬜ Proximity flows (ISO 18013-5 BLE/NFC device retrieval) and online (ISO 18013-7) — require
  mobile hardware; the `mso_mdoc` format and device binding exist, the radio transport does not

## Phase 4 — Conformance
- ✅ Requirement traceability matrix (capability → spec → code → test): `docs/TRACEABILITY.md`
- ✅ Conformance & interoperability testing guide: `docs/CONFORMANCE.md`
- 🟡 Documented mapping to exact ARF requirement IDs (matrix maps by capability; per-ID pinning ongoing)
- ⬜ Recorded OpenID Foundation conformance-suite runs (`docs/conformance-runs/`)
- ⬜ EU Launchpad interop event results
