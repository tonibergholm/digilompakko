# Productionization — from this reference toward a real Suomi.fi Wallet

This note describes what it would take to evolve Digilompakko from a protocol **reference** into a
production European Digital Identity Wallet of the kind DVV is procuring as the *Suomi.fi Wallet*.
It is a design/gap document, not a commitment or a claim of readiness. Read `COMPLIANCE.md` §6 and
`TRACEABILITY.md` first; this note expands the "what's missing" side into a concrete plan.

The short version: this repo gets the **protocols and data formats** right (SD-JWT VC, mdoc,
OpenID4VCI/VP, HAIP crypto, status lists, holder binding). Production is dominated by everything
*around* the protocols — secure hardware, real identity proofing, trust infrastructure, scale,
privacy guarantees, certification, and law. That is where the bulk of the work and risk lives.

## 1. The real Finnish ecosystem

A production deployment is not one codebase but a set of cooperating institutions, each owning part
of the trust chain:

- **DVV** — wallet provider: builds and operates the wallet solution and issues the holder's digital
  identity into it; runs the backend and the Suomi.fi integration.
- **National Police Board** — issues the eID (a digital identity document comparable to a passport/ID
  card) that lives in the wallet.
- **Traficom** — mobile driving licence (mDL) provider, pending the EU Driving Licence Directive.
- **Other public bodies & private issuers** — attestation (EAA) providers building credentials for
  the wallet ecosystem.
- **Relying Parties** — public and private services consuming presentations, registered and issued
  access certificates.
- **EU Commission / Member State** — Trusted Lists, the registrar, conformance and notification.

Digilompakko today plays the issuer, holder, and verifier roles in one repo for demonstration. In
production these are separate, independently operated, mutually distrusting systems connected only by
the standards and the trust framework.

## 2. The major gaps and what closing them entails

### 2.1 Secure key storage (WSCD) — the single biggest item

The wallet's private keys must live in a **Wallet Secure Cryptographic Device**: the phone's secure
element / TEE (Android StrongBox Keystore, iOS Secure Enclave) or a certified external device, with
**key attestation** proving to issuers that keys are hardware-bound and non-exportable. This repo
abstracts the boundary (`core/src/keystore.ts`: `WalletKeyStore`/`JwsSigner`), so the work is to
implement that interface against platform crypto APIs, add attestation, and use **per-credential**
(ideally single-use) keys. The WSCD typically requires **Common Criteria** certification — a long,
expensive process that constrains the whole architecture.

### 2.2 Native mobile apps

A real wallet is a native **Android (Kotlin)** and **iOS (Swift)** app — for secure storage,
biometrics, background NFC/BLE, and app-attestation — not a web app. The EU reference wallet is
native for exactly these reasons. This repo's TypeScript wallet is a protocol demonstration; the
holder app would be rebuilt natively (the issuer/verifier services can remain server-side). The
`core` library's logic is the reusable spec; the holder UI/keystore are platform work.

### 2.3 Real PID issuance and identity proofing

Issuing the PID must be bound to the **Population Information System** and to **strong identification**
(today: bank credentials, the mobile certificate, the citizen certificate; in future the wallet
itself). The Police-issued eID becomes an official document. This is DVV/Police domain: identity
proofing, lifecycle (renewal, suspension on loss/theft, death), and binding to the register — none of
which a demo can simulate responsibly. The demo's fictional `Toni Bergholm` PID stands in for this.

### 2.4 Trust infrastructure

Production trust is not a static allow-list. It needs:

- **EU/Member-State Trusted Lists** and the **registrar** — issuers and RPs are discoverable and
  verifiable through signed national lists; the wallet and verifier resolve trust anchors from them.
- **RP registration + access certificates** — RPs are registered, issued X.509 access certificates
  declaring entitled attributes, and the wallet enforces those at presentation time (intent
  registration / data-minimisation). This repo models the *gate* (`core/src/rp-registry.ts`) but not
  the certificates or the list plumbing.
- **Issuer trust anchors** for both SD-JWT VC (`x5c`/trusted JWKS) and mdoc (`issuerAuth` x5chain).

The `TrustResolver` interface is the seam to swap the static resolver for a real Trusted List client.

### 2.5 Revocation and credential lifecycle at scale

PID already uses an IETF **Token Status List**; production needs this hosted at scale with **privacy**
(large status lists / herd anonymity so a fetch doesn't reveal which credential is checked), plus
credential **refresh / re-issuance**, mdoc status (currently absent in our mdoc subset), and clear
lifecycle on revoke/suspend/expire.

### 2.6 Backend hardening

Issuer signing keys belong in an **HSM**, not in process memory. Add horizontal scaling, persistent
storage (not in-memory maps), rate limiting, audit logging, observability, key rotation and a
documented **key ceremony**, disaster recovery, and high availability. The issuer/verifier here are
single-process demos with in-memory state — deliberately.

### 2.7 Privacy by design

Beyond selective disclosure (which this repo does): **unlinkability** across presentations (batch
issuance of single-use credentials so verifiers and issuers can't correlate), no "phone-home" on
presentation, minimal logging of personal data, and a defensible **GDPR DPIA**. These are
architectural commitments, not features bolted on later.

### 2.8 Standards completeness

To pass conformance and interoperate, finish: full **ISO 18013-5** (proper SessionTranscript,
`deviceMac` as well as `deviceSignature`, and **proximity** retrieval over BLE/NFC), **ISO 18013-7**
for online mdoc, **OpenID4VP** request-object signing/encryption and full **DCQL**, and complete
**HAIP** conformance for both credential formats. See `docs/CONFORMANCE.md` for how to test.

### 2.9 Certification, security assurance, and law

- **eIDAS conformity assessment** by a CAB; WSCD certification (Common Criteria); formal **threat
  modelling**, independent **penetration testing**, and **supply-chain** assurance (SBOM, signed
  builds, dependency policy).
- **Legal/operational**: GDPR DPIA, **accessibility** (WCAG 2.1 AA), Finnish + Swedish (and English)
  localisation, user support, incident response, and governance.

## 3. What this reference already gives a production effort

Not nothing — the expensive-to-get-right *correctness* core is here and tested:

- A clean, audited-library-based implementation of **SD-JWT VC** and **mdoc** issue/verify with real
  selective disclosure and holder/device binding (`packages/core`).
- The **protocol shapes** for OpenID4VCI (pre-auth + Authorization Code/PAR/PKCE) and OpenID4VP
  (DCQL, nonce/aud replay protection) as runnable, readable services.
- **Seams** for the hard production pieces: `WalletKeyStore` (WSCD), `TrustResolver` (Trusted Lists),
  `RelyingPartyRegistry` (RP access), `Oid4vcError` (error model).
- **Adversarial test patterns** (revoked → invalid, replay → fail, untrusted issuer → rejected,
  over-entitled RP → denied) that a production suite should keep and extend.
- A **traceability matrix** and **conformance guide** to drive the external testing.

A production team could lift `packages/core`'s structure and tests as a specification oracle while
building the native, hardware-backed, institutionally-integrated system around it.

## 4. A pragmatic migration path

1. **Native holder app + real WSCD** (Android/iOS, secure element, attestation) implementing the
   `WalletKeyStore` interface — the foundational, longest-lead item.
2. **Trust infrastructure**: Trusted List client behind `TrustResolver`; RP access certificates.
3. **Real PID/eID issuance** with Police + Population Information System and strong identification.
4. **Backend hardening**: HSM signing, persistence, scale, audit, DR.
5. **Standards completeness**: full 18013-5/-7, proximity, OpenID4VP request security, full HAIP.
6. **Privacy**: batch/single-use credentials, unlinkability, DPIA.
7. **Certification**: WSCD CC, eIDAS CAB audit, pen test, conformance runs, notification.

## 5. Open questions to resolve early

- Which WSCD strategy (platform secure element vs. certified external device) and its CC scheme?
- Batch issuance / unlinkability design — and its cost on issuer throughput and status lists.
- mdoc revocation approach (status in the MSO vs. short-lived mdocs).
- How RP access certificates are issued, distributed, and checked offline in the wallet.
- Governance of the issuer signing key ceremony and rotation.

---

*This document is intentionally honest about scope. Digilompakko is a high-fidelity protocol
reference; the journey to a notified, certified Suomi.fi Wallet is mostly the work catalogued above.*
