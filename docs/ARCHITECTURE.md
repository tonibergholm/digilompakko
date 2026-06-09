# Architecture

## Monorepo layout

```
digilompakko/
├── docs/
│   ├── COMPLIANCE.md        # spec mapping & gap-to-certification (read this first)
│   ├── ARCHITECTURE.md      # this file
│   ├── ROADMAP.md           # phased plan + status
│   ├── TRACEABILITY.md      # capability → spec → code → test matrix
│   ├── CONFORMANCE.md       # how to run external conformance suites
│   └── PRODUCTIONIZATION.md # what a real Suomi.fi Wallet needs beyond this reference
├── packages/
│   └── core/                # shared, framework-agnostic library (no HTTP)
│       └── src/
│           ├── crypto.ts         # P-256 key gen, ES256 sign/verify, hashing (jose + node:crypto)
│           ├── sd-jwt.ts         # SD-JWT VC issue/verify, disclosures, KB-JWT
│           ├── mdoc.ts           # ISO 18013-5 mdoc/mDL (CBOR + COSE_Sign1), DeviceAuth
│           ├── status-list.ts    # IETF Token Status List (statuslist+jwt)
│           ├── trust.ts          # TrustResolver + StaticTrustResolver (allow-list)
│           ├── keystore.ts       # WSCD boundary: WalletKeyStore / JwsSigner / SoftwareKeyStore
│           ├── pkce.ts           # PKCE (RFC 7636, S256)
│           ├── rp-registry.ts    # Relying Party registration + entitlement gate
│           ├── request-object.ts # OpenID4VP signed request objects (JAR, RFC 9101)
│           ├── errors.ts         # Oid4vcError + sendError
│           ├── types.ts          # shared types
│           └── index.ts
└── apps/
    ├── issuer/              # OpenID4VCI 1.0 service (Express)
    ├── verifier/           # OpenID4VP 1.0 service (Express)
    └── wallet/             # holder service + minimal web UI
```

## Component responsibilities

### `packages/core`
Pure TypeScript, no HTTP. The trust-critical code lives here so it can be unit-tested and reused.
- **crypto.ts** — generate P-256 JWKs, sign/verify ES256, SHA-256 digests, salts, thumbprints.
- **sd-jwt.ts** — build/verify SD-JWT VC (`<jws>~<disclosure>~...~<kbjwt>`), salted-hash `_sd`
  digests, selective disclosure, Key Binding JWT. Accepts a `JWK | JwsSigner` so the holder can
  sign through the keystore.
- **mdoc.ts** — issue/verify ISO 18013-5 mdoc (`mso_mdoc`): CBOR encoding, COSE_Sign1 over the MSO
  (value digests + deviceKey), per-item selective disclosure, nonce-bound DeviceAuth, and an
  optional Token Status List reference in the MSO.
- **status-list.ts** — build/read signed `statuslist+jwt` tokens over a DEFLATE-compressed bitstring.
- **trust.ts** — `TrustResolver` interface + `StaticTrustResolver` (trusted-issuer allow-list that
  resolves keys from issuer metadata). The seam for a real Trusted List client.
- **keystore.ts** — the WSCD boundary: `WalletKeyStore` / `JwsSigner` (sign without exposing the
  private key) + `SoftwareKeyStore` (demo). A hardware-backed store plugs in behind the interface.
- **pkce.ts** — S256 PKCE challenge/verify.
- **rp-registry.ts** — `RelyingPartyRegistry` with registration + attribute-entitlement enforcement.
- **request-object.ts** — sign/verify OpenID4VP Authorization Requests (JAR).
- **errors.ts** — `Oid4vcError` (registry codes) + `sendError` for spec-shaped HTTP errors.
- **types.ts** — `CredentialOffer`, `PresentationRequest`, DCQL shapes, `MdocClaims`, etc.

### `apps/issuer` (OpenID4VCI 1.0 + Token Status List)
| Route | Spec purpose |
|-------|--------------|
| `GET /.well-known/openid-credential-issuer` | Issuer metadata + JWKS; advertises `dc+sd-jwt` and `mso_mdoc` |
| `POST /offer` | Create a Credential Offer (PID or, via `credential_configuration_id`, the mDL) |
| `POST /par` | Pushed Authorization Request (RFC 9126) |
| `GET /authorize` | Authorization endpoint (demo auto-approves) → authorization code |
| `POST /token` | Pre-authorized **and** authorization_code (PKCE) grants → access token + `c_nonce` |
| `POST /credential` | Verify holder PoP → SD-JWT VC **or** mdoc, with a status index |
| `GET /statuslist` | Signed Status List Token (`statuslist+jwt`) |
| `POST /admin/revoke` | Demo admin: flip a status bit |

### `apps/verifier` (OpenID4VP 1.0)
| Route | Spec purpose |
|-------|--------------|
| `GET /jwks.json` | Verifier (RP) public key for signed request objects |
| `GET /rp/:clientId` | RP registration lookup |
| `POST /presentation/request` | Create a session (`?format=mso_mdoc` for the mDL); entitlement-gated |
| `GET /presentation/request/:id` | Returns a **signed** request object (JAR) with DCQL + nonce |
| `POST /presentation/response` | Verify `vp_token` (both formats) → trust + revocation → result |
| `GET /presentation/result/:id` | Poll a session result |

### `apps/wallet`
Holds keys (via `SoftwareKeyStore` — the WSCD boundary) and credentials (in-memory), drives both
protocols for **both formats**, verifies the verifier's signed request object before disclosing, and
serves a tiny web UI: **get PID (pre-auth / Auth Code+PAR+PKCE) or mDL → present → see result**.

## Trust, revocation & holder binding
- **Trust** is resolved through `TrustResolver`; the demo uses a static allow-list reading issuer
  metadata JWKS. Swap in a Trusted List client without touching the verifier.
- **Revocation** uses the IETF Token Status List for **both** SD-JWT VC (status in the payload) and
  mdoc (status in the MSO); the verifier fetches the signed list and rejects revoked credentials.
- **Holder/device binding** is real end-to-end: SD-JWT VC via `cnf` + KB-JWT, mdoc via the MSO
  `deviceKey` + a nonce-bound DeviceAuth. The holder signs through the keystore (WSCD), never with a
  raw key.
- **Request authenticity**: the verifier signs its Authorization Request (JAR); the wallet verifies
  that signature against the RP's published key before responding.

## Data flow sequence
See `COMPLIANCE.md` §3 for the numbered issuance + presentation sequence. mdoc follows the analogous
flow with CBOR/COSE structures in place of JWS/JWT.
