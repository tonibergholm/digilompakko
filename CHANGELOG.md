# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses
[Conventional Commits](https://www.conventionalcommits.org).

## [Unreleased]

### Added — mdoc revocation + OpenID4VP signed request objects
- **mdoc revocation**: `issueMdoc` embeds a Token Status List reference in the MSO; the issuer
  assigns mDLs a status index; `verifyMdocPresentation` surfaces it; the verifier fetches the status
  list and rejects revoked mDLs (parity with PID). (`core/src/mdoc.ts`)
- **OpenID4VP signed request objects (JAR, RFC 9101)**: `core/src/request-object.ts`
  (`signRequestObject`/`verifyRequestObject`); the verifier signs its Authorization Request and
  publishes its key at `/jwks.json`; the wallet verifies the RP signature before responding.
- Tests for mdoc status surfacing and JAR sign/verify (incl. forged-key and tamper rejection).

### Added — mdoc/mDL over the HTTP layer
- Issuer issues `mso_mdoc` end-to-end: `/offer` accepts a `credential_configuration_id`, and the
  credential endpoint issues an mdoc bound to the holder's device key when the mDL is requested.
- Verifier supports an `mso_mdoc` presentation request (`/presentation/request?format=mso_mdoc`)
  with mdoc DCQL and verifies the mdoc `vp_token` (issuer key resolved from the trusted issuer).
- Wallet stores and presents both formats; the UI exposes mDL get/present. PID (SD-JWT) unchanged.
- Documented: this mdoc subset has no Token Status List revocation yet (PID does).

### Added — Phase 4: conformance documentation
- **Requirement traceability matrix** (`docs/TRACEABILITY.md`): capability → spec → code → test
  across formats, issuance, presentation, trust/revocation/keys, RP governance, and crypto.
- **Conformance & interoperability testing guide** (`docs/CONFORMANCE.md`): how to point the OpenID
  Foundation conformance suite and the EU Launchpad at the services, plus the path to certification.

### Added — Phase 3: real-world hardening
- **WSCD key-storage abstraction** (`packages/core/src/keystore.ts`): `WalletKeyStore` / `JwsSigner`
  / `SoftwareKeyStore`. Private keys never leave the store; the SD-JWT VC and mdoc credential APIs
  now accept a `JWK | JwsSigner`, so the wallet signs through the keystore (WSCD boundary).
- **Authorization Code flow** with **PAR** (RFC 9126) and **PKCE** (RFC 7636), alongside the
  pre-authorized code flow: issuer `/par`, `/authorize`, and an `authorization_code` token grant;
  `core/src/pkce.ts` with S256 verification.
- **Relying Party registration** (`core/src/rp-registry.ts`): registry + attribute-entitlement gate
  enforcing data minimisation; verifier exposes `/rp/:clientId` and self-checks entitlement.
- Wallet refactored onto the keystore; UI offers both issuance flows. Issuer metadata advertises
  the authorization and PAR endpoints.
- Tests for keystore signing/non-export, end-to-end keystore holder, PKCE, and RP entitlement.

### Added — Phase 2: second credential format (ISO 18013-5 mdoc/mDL)
- **mdoc/mDL** (`packages/core/src/mdoc.ts`): CBOR + COSE_Sign1 (`mso_mdoc`) issuance and
  verification with per-item selective disclosure (random salts + SHA-256 value digests in the MSO).
- **Device binding** via a `deviceAuth` COSE_Sign1 over a nonce-bound DeviceAuthentication
  structure (the mdoc analogue of the SD-JWT Key Binding JWT).
- Issuer metadata now advertises both `dc+sd-jwt` and `mso_mdoc` (format negotiation).
- Headless demo and tests cover mdoc selective disclosure, replay, forged-issuer, and device binding.
- Documented 18013-5 simplifications (SessionTranscript, `deviceSignature`-only) in COMPLIANCE §6.

### Added — Phase 1: trust & lifecycle
- **Token Status List** (`packages/core/src/status-list.ts`): build/read signed `statuslist+jwt`
  tokens with DEFLATE-compressed bitstrings.
- Issuer publishes a Status List Token at `/statuslist`, assigns each credential a status index,
  embeds a `status` reference in the SD-JWT VC, and exposes `/admin/revoke`.
- Verifier fetches and checks the Status List and **rejects revoked credentials**.
- **Pluggable trust resolution** (`TrustResolver` + `StaticTrustResolver`): verifier enforces a
  trusted-issuer allow-list and resolves issuer keys from published metadata.
- **Structured error model** (`Oid4vcError`) with OpenID4VC/OAuth-style codes; spec-shaped HTTP
  error responses via `sendError`.
- Verification now returns `issuerClaims` (always-visible issuer-signed claims).
- Tests for status list roundtrip, revocation, status-token signature, and trust allow-list.
- Project governance: `CLAUDE.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
  GitHub Actions + Woodpecker CI, PR and issue templates.

## [0.1.0] — Phase 0

### Added
- Monorepo (npm workspaces): `packages/core`, `apps/issuer`, `apps/verifier`, `apps/wallet`.
- SD-JWT VC issuance/verification with selective disclosure and ES256 holder binding (KB-JWT).
- OpenID4VCI 1.0 pre-authorized code issuance flow.
- OpenID4VP 1.0 presentation flow with a DCQL query and nonce/audience replay protection.
- Headless demo, minimal wallet web UI, and a `node:test` suite.
- `docs/COMPLIANCE.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`; Apache-2.0 license.
