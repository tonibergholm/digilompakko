# Digilompakko 🇫🇮

> Open-source **EUDI digital identity wallet** demo — issuer + wallet + verifier — aligned with the
> EU **Architecture & Reference Framework (ARF) 2.x** and the **OpenID4VC High Assurance
> Interoperability Profile (HAIP) 1.0**.

This project demonstrates the complete **issue → hold → present → verify** flow for a European
Digital Identity Wallet using **SD-JWT VC** credentials over **OpenID4VCI** and **OpenID4VP**, with
real selective disclosure and ES256 holder binding.

It exists alongside Finland's *Suomi.fi Wallet* (being procured by DVV under eIDAS 2.0) as an
approachable, readable TypeScript reference. **It is a learning/conformance reference, not a
certified production wallet** — see [`docs/COMPLIANCE.md` §6](docs/COMPLIANCE.md) for the honest gap
list.

## Why it's "spec compliant"

Compliance is a *stack*, not one document. This repo implements the core of it and documents the rest:

| Concern | Standard | Status |
|---------|----------|--------|
| Credential format | IETF **SD-JWT VC** (`dc+sd-jwt`) | ✅ |
| Selective disclosure | salted-hash digests in `_sd` | ✅ |
| Holder binding | `cnf` + **Key Binding JWT** | ✅ |
| Issuance | **OpenID4VCI 1.0** (pre-auth flow) | ✅ |
| Presentation | **OpenID4VP 1.0** + **DCQL** | ✅ |
| Crypto suite | **ES256 / P-256** (HAIP) | ✅ |
| Revocation | **IETF Token Status List** (`statuslist+jwt`) | ✅ |
| Trust resolution | pluggable resolver + static trusted list | ✅ |
| mdoc / ISO 18013-5, real trusted lists, secure element | — | ⬜ roadmap |

Full mapping with requirement traceability: **[`docs/COMPLIANCE.md`](docs/COMPLIANCE.md)**,
**[`docs/TRACEABILITY.md`](docs/TRACEABILITY.md)** (capability → code → test), and
**[`docs/CONFORMANCE.md`](docs/CONFORMANCE.md)** (how to run the external conformance suites).

## Architecture

```
ISSUER ──OpenID4VCI──▶ WALLET ──OpenID4VP──▶ VERIFIER
(PID provider)         (holder)              (relying party)
            shared crypto + SD-JWT VC: packages/core
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick start

```bash
npm install

# Run the headless end-to-end proof (no servers needed):
npm run demo

# Run the test suite (selective disclosure, replay, holder binding, tamper):
npm test

# Or run the three services + open the wallet UI:
npm start
# then visit http://localhost:4000
```

In the UI: click **Receive credential** (OpenID4VCI), then tick which claims to share and click
**Present** (OpenID4VP). The verifier returns exactly — and only — the claims you disclosed.

## Layout

```
packages/core   trust-critical library: crypto, SD-JWT VC issue/verify, KB-JWT
apps/issuer     OpenID4VCI 1.0 issuer (port 4001)
apps/verifier   OpenID4VP 1.0 verifier (port 4002)
apps/wallet     holder wallet + web UI (port 4000)
scripts/demo.ts headless end-to-end demo
docs/           COMPLIANCE.md · ARCHITECTURE.md · ROADMAP.md
```

## Revocation demo

```bash
npm start
# obtain a credential in the UI (or: curl -X POST localhost:4000/api/get-credential)
curl -X POST localhost:4001/admin/revoke -H 'content-type: application/json' -d '{"idx":0}'
# present again -> verifier now returns valid:false with "credential_revoked"
```

## Contributing

Issues and PRs welcome. **Please read [`CLAUDE.md`](CLAUDE.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md)
first** — all changes use a **worktree + PR-into-`main`** workflow, Conventional Commits, and must
keep `npm run build` and `npm test` green. The [roadmap](docs/ROADMAP.md) lists the next compliance
modules (mdoc/ISO 18013-5, real trusted lists, secure-element key storage). Keep trust-critical code
in `packages/core` with tests. See also [`SECURITY.md`](SECURITY.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

[Apache-2.0](LICENSE). EUPL-1.2 is a documented alternative for EU-institutional alignment.

## References

- [EU ARF](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/)
- [OpenID4VC HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
- [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) · [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [IETF SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
- [EU reference implementations](https://github.com/eu-digital-identity-wallet)
