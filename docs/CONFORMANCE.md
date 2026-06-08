# Conformance & Interoperability Testing Guide

Spec-conformance for an EUDI wallet is established by **external test suites and audits**, not by a
project's own tests. This guide explains how to point the recognised suites at this implementation,
what they cover, and where the path to formal certification leads. (Our `npm test` suite proves
internal correctness; it is necessary but not sufficient for conformance.)

> Reality check: a *certified* wallet additionally needs hardware-backed key storage, real PID/eID
> integration, trusted-list trust, and a Conformity Assessment Body (CAB) audit. See
> `COMPLIANCE.md` §6. This guide covers the protocol-conformance steps you *can* run today.

## 1. OpenID Foundation Conformance Suite

The OIDF runs official conformance tests for **OpenID4VCI**, **OpenID4VP**, and **SD-JWT VC / HAIP**.

- Suite: https://www.certification.openid.net/ (hosted) or self-hosted from
  `openid-certification/conformance-suite`.
- Relevant test plans: *OpenID for Verifiable Credential Issuance*, *OpenID for Verifiable
  Presentations*, and the *HAIP* profiles.

How to point it at this repo:

1. Run the services on a publicly reachable URL (or via a tunnel), e.g. set `ISSUER_URL` /
   `VERIFIER_URL` env vars and `npm start`.
2. As an **issuer** test: give the suite the issuer base URL; it reads
   `/.well-known/openid-credential-issuer`, runs the pre-auth and Authorization Code (PAR+PKCE)
   flows, and checks the returned SD-JWT VC.
3. As a **verifier** test: the suite acts as a wallet, fetching `/presentation/request/:id` and
   posting a `vp_token`; assert the verification result.
4. As a **wallet** test: drive `apps/wallet` against the suite's reference issuer/verifier.

Known gaps to expect failures on (documented, not silent): full 18013-5 SessionTranscript,
`deviceMac`, request-object signing/encryption, and any HAIP feature on the roadmap.

## 2. EU Launchpad / interoperability events

The European Commission provides the **EUDI Wallet Launchpad** and runs interoperability test events
against the reference implementations.

- Dev Hub: https://eu-digital-identity-wallet.github.io/Build/
- Launchpad testing: the Commission's "Launchpad Testing" pages.

Use these to test cross-implementation issuance/presentation against the EU reference issuer and
verifier. Track results per credential format (`dc+sd-jwt`, `mso_mdoc`).

## 3. Path to certification (informational)

Formal status under eIDAS 2.0 is **not** a test you run; it is a process:

1. Meet the ARF + implementing-acts requirements (incl. WSCD, trust infrastructure).
2. Certify the WSCD / wallet solution per the relevant scheme (e.g. Common Criteria).
3. Engage a **Conformity Assessment Body (CAB)** for the eIDAS audit.
4. Member-state notification.

This repo deliberately stops before step 1's hardware/PID requirements; it is a protocol reference.

## 4. Local conformance hooks

- `npm test` — internal correctness incl. adversarial security tests (revocation, replay, holder
  binding, RP entitlement). Required green before any PR.
- `npm run demo` — headless end-to-end smoke test of both credential formats; wired into CI.
- See `TRACEABILITY.md` for the capability→code→test map the external suites exercise.

## 5. Recording results

When you run an external suite, capture the run (date, suite version, profile, pass/fail per test)
under `docs/conformance-runs/` and link it from `ROADMAP.md` Phase 4 so progress toward
interoperability is auditable over time.
