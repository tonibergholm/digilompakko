# Architecture

## Monorepo layout

```
digilompakko/
├── docs/
│   ├── COMPLIANCE.md     # spec mapping & traceability (read this first)
│   ├── ARCHITECTURE.md   # this file
│   └── ROADMAP.md
├── packages/
│   └── core/             # shared, framework-agnostic library
│       └── src/
│           ├── crypto.ts # P-256 key gen, ES256 sign/verify (jose)
│           ├── sd-jwt.ts # SD-JWT VC issue/verify, disclosures, KB-JWT
│           ├── types.ts  # shared types
│           └── index.ts
└── apps/
    ├── issuer/           # OpenID4VCI 1.0 service (Express)
    ├── verifier/         # OpenID4VP 1.0 service (Express)
    └── wallet/           # holder service + minimal web UI
```

## Component responsibilities

### `packages/core`
Pure TypeScript, no HTTP. The trust-critical code lives here so it can be unit-tested and reused.
- **crypto.ts** — generate P-256 JWKs, sign/verify ES256, thumbprints.
- **sd-jwt.ts** — build SD-JWT VC (`<jws>~<disclosure>~...~<kbjwt>`), compute salted-hash digests
  for the `_sd` array, parse/verify, select disclosures, create & verify the Key Binding JWT.
- **types.ts** — `CredentialOffer`, `SdJwtVc`, `PresentationRequest`, DCQL query shapes.

### `apps/issuer` (OpenID4VCI 1.0)
| Route | Spec purpose |
|-------|--------------|
| `GET /.well-known/openid-credential-issuer` | Issuer metadata |
| `POST /offer` | Create a credential offer (demo convenience) |
| `POST /token` | Pre-authorized code → access token + `c_nonce` |
| `POST /credential` | Verify holder PoP, return SD-JWT VC |

### `apps/verifier` (OpenID4VP 1.0)
| Route | Spec purpose |
|-------|--------------|
| `GET /.well-known/...` | Verifier (client) metadata |
| `POST /presentation/request` | Create Authorization Request with DCQL + nonce |
| `GET /presentation/request/:id` | Wallet fetches the request object |
| `POST /presentation/response` | Receive `vp_token`, verify, return result |

### `apps/wallet`
Holds keys + credentials (in-memory for the demo), drives both protocols, and serves a tiny web UI
to walk a human through: **accept offer → receive credential → respond to verifier → see result**.

## Trust model (demo)
For v0 the issuer's public key is shared with the verifier via the issuer's metadata endpoint and a
small static allow-list (`trustedIssuers`). Phase 1 replaces this with a pluggable trust resolver
(Trusted Lists). Holder binding is real end-to-end (`cnf` + KB-JWT), not stubbed.

## Data flow sequence
See `COMPLIANCE.md` §3 for the numbered issuance + presentation sequence each endpoint implements.
