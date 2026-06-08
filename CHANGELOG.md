# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses
[Conventional Commits](https://www.conventionalcommits.org).

## [Unreleased]

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
