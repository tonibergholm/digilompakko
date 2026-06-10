# Security Audit — Digilompakko

**Date:** 2026-06-10 · **Scope:** `packages/core`, `apps/issuer`, `apps/verifier`, `apps/wallet`, `scripts/`, `mobile/`, dependencies, CI/config.
**Method:** Full manual source review of all TS source + tests, mobile (Swift/Kotlin) review, `npm audit`, secrets scan, CI/config review. All findings verified against the code (file:line cited).

Context: this is a documented demo (software keys, in-memory state, no real PID). Findings marked **[demo-accepted]** are known simplifications per `docs/COMPLIANCE.md` §6 / `SECURITY.md`; everything else is a genuine implementation gap that should be fixed regardless of demo status.

---

## Prioritized TODO list

### P0 — Fix now (real vulnerabilities)

- [x] **1. XSS in wallet UI via issuer/verifier-controlled strings** — `apps/wallet/src/server.ts:125-126`
  `innerHTML` is built by string concatenation with `r.vct` (from the issuer's credential) and `r.error` (error messages embedding attacker-controlled values, e.g. `clientId` from an unverified JAR in `wallet.ts:179`). A rogue issuer/verifier executes script in the wallet origin.
  **Fix:** use `textContent`/DOM construction; add CSP + `X-Content-Type-Options: nosniff` to the `/` HTML response.

- [x] **2. SSRF guard bypassed by redirects and allows private HTTPS IPs** — `packages/core/src/http.ts:32-69`
  `assertSafeUrl` only blocks non-HTTPS for non-loopback hosts: `https://169.254.169.254/`, `https://10.x.x.x/` etc. pass. Worse, `fetch` follows redirects internally and the guard is never re-applied per hop, so any allowed origin can 302 to internal services. Used by trust resolver, status-list and app fetches.
  **Fix:** block private/link-local/ULA/metadata ranges; `redirect: "manual"` + re-validate each hop (with hop limit); pin resolved IP against DNS rebinding.

- [x] **3. Unauthenticated revocation + PII endpoints** — `apps/issuer/src/server.ts:288-300`
  `POST /admin/revoke` lets any network client revoke any credential index (DoS against all holders); `GET /admin/issued` leaks subject names. **Fix:** require an admin bearer token; gate PII behind authorization.

- [x] **4. Status List token never expires → revocation bypass via stale-list replay** — `packages/core/src/status-list.ts:74, 90-128`
  Token has `iat` only; `readStatus` enforces no `exp`/`maxTokenAge`. A pre-revocation snapshot stays valid forever, so a revoked credential can verify as VALID.
  **Fix:** `.setExpirationTime()` (+ `ttl` per draft-ietf-oauth-status-list) at build; require `exp` and enforce `maxTokenAge` at read. Add adversarial test.

- [x] **5. Wallet POSTs vp_token to unvalidated `response_uri`** — `apps/wallet/src/wallet.ts:143-147`
  PII-bearing `vp_token` is sent to whatever `response_uri` the request object names, with no origin check against the verified `client_id`, via raw `fetch` (no SSRF guard/timeout).
  **Fix:** require `new URL(response_uri).origin === new URL(client_id).origin`; route through `safeFetch`.

### P1 — Fix soon (protocol/robustness gaps)

- [x] **6. Verifier-trust check uses `startsWith`** — `apps/wallet/src/wallet.ts:177`
  `http://localhost:4002.evil.com` passes a prefix match for `http://localhost:4002`. **Fix:** exact `URL.origin` equality against the allowlist.

- [x] **7. Raw `fetch` bypasses `safeFetch` hardening across the wallet** — `apps/wallet/src/wallet.ts:95, 165`; `apps/wallet/src/server.ts:27, 38, 66`
  `request_uri` and issuer endpoints fetched with no timeout, size cap, or URL guard, contradicting the `http.ts` policy. **Fix:** route all egress through `safeFetch*`.

- [x] **8. mdoc: docType not bound between Document and MSO; `validFrom`/`signed` unchecked** — `packages/core/src/mdoc.ts:231-233, 272-273`
  `docType` is read from the holder-built Document and never compared to the issuer-signed MSO docType (doc-type confusion); only `validUntil` is checked, so not-yet-valid credentials pass. **Fix:** assert equality; enforce `validFrom ≤ now ≤ validUntil`.

- [x] **9. Body size cap applied after full buffering** — `packages/core/src/http.ts:74-81`
  `await res.text()` materializes the whole body before the 1 MiB check (and counts UTF-16 units, not bytes) → memory-exhaustion DoS from a malicious endpoint. **Fix:** stream and abort at `MAX_BODY_BYTES` bytes.

- [x] **10. Unbounded in-memory Maps → memory DoS** — `apps/issuer/src/server.ts:55-60`; `apps/verifier/src/server.ts:100`
  Unauthenticated `/offer`, `/par`, `/presentation/request` create entries that are only lazily evicted on same-key access. **Fix:** periodic TTL sweep + size caps.

- [x] **11. Pre-authorized_code never expires; no tx_code** — `apps/issuer/src/server.ts:131-147, 205-208`
  All other grants have TTLs; the pre-auth code is redeemable indefinitely and without a transaction code (HAIP recommends one). **Fix:** stamp `createdAt`, enforce short TTL; add `tx_code` to offer/redemption.

- [x] **12. Auth code not bound to client; no client auth on PAR** — `apps/issuer/src/server.ts:150-158, 192-209`
  `client_id` is never persisted from PAR → authorize → token; only PKCE protects the code. **Fix:** verify `client_id` across the chain; authenticate confidential clients. (Absent `redirect_uri` validation is **[demo-accepted]** but must precede any real deployment.)

- [x] **13. Presentation result readable by anyone with the session id; never purged** — `apps/verifier/src/server.ts:235-239`
  The id travels in `request_uri` handed to the wallet; result contains disclosed PII. **Fix:** bind retrieval to RP session; purge after read/TTL.

- [x] **14. Fix shell-quote advisory (currently failing the CI audit gate)** — root devDependency via `concurrently` (GHSA-w7jw-789q-3m8p, dev-only)
  **Fix:** `npm audit fix` in a worktree; add the missing `npm audit --audit-level=high` step to `.woodpecker.yml` to match GitHub CI.

### P2 — Hardening / defense-in-depth

- [x] **15. Pin `algorithms: ["ES256"]` on every `jwtVerify`** — `packages/core/src/sd-jwt.ts:135,164`; `status-list.ts:99`; `request-object.ts:34,92`; `apps/issuer/src/server.ts:243-251`; also validate COSE alg (-7) in `coseSign1Verify` (`mdoc.ts:74-81`). Not currently exploitable (P-256 keys), but nothing enforces the HAIP-mandated suite.
- [x] **16. Access-token double-spend race on credential endpoint** — `apps/issuer/src/server.ts:226-275`: token deleted only after `await`s; consume it synchronously like the verifier does (`verifier:169`).
- [x] **17. CBOR decode limits** — `packages/core/src/mdoc.ts:23-26`: attacker CBOR decoded pre-signature-check with no depth/size bound; duplicate keys silently last-win. Add limits; reject duplicate keys in MSO/issuerAuth.
- [x] **18. KB-JWT freshness + `nbf`** — `packages/core/src/sd-jwt.ts:164-177`: enforce an `iat` max-age window on the KB-JWT and honour `nbf` on the credential.
- [x] **19. Trust resolver key handling** — `packages/core/src/trust.ts:36-42`: takes `jwks.keys[0]` with no `kty/crv/use` validation, no `kid` selection, cache never expires. Validate key shape, select by `kid`, add TTL.
- [x] **20. Remove/demote weak `verifyRequestObject` export** — `packages/core/src/request-object.ts:31-39`: signature-only JAR check exported alongside the hardened `verifyPresentationRequest`; an app picking the wrong one loses aud/allowlist binding.
- [x] **21. Misc small items** — negative status index returns VALID (`status-list.ts:126-128`); `_sd_alg` ignored (`sd-jwt.ts:145`); PKCE compare not constant-time (`pkce.ts:17`); `Math.random()` nonce in `scripts/demo.ts:32`; no decoy digests (unlinkability leak, `sd-jwt.ts:52`); `__proto__` path guard in `dcql.ts:31-33`; security headers (CSP/XCTO/Referrer-Policy) absent on all apps; mobile JAR key fetched from URL named inside the unverified JAR (`mobile/*/Wallet.*` — pin RP keys via trust registry when productionizing); document an HTTPS option (mkcert) for real-device mobile testing.

### P3 — Missing adversarial tests (per CLAUDE.md testing policy)

- [x] **22. Add negative tests** for: stale/expired status-list token; SSRF over HTTPS to private IPs + redirect bypass; oversized response body; mdoc value tampering with the *real* issuer key (digest mismatch); mdoc docType confusion and `validFrom`; SD-JWT disclosure add/remove/duplicate after presentation (`sd_hash` mismatch); expired credential (`exp` branch is never exercised); alg-confusion / ES256-only pinning; CBOR depth/duplicate keys; negative status index.

---

## What's already good

Strict TS everywhere; all signing via `jose` (no hand-rolled crypto); no secrets in the repo; SHA-pinned, least-privilege CI with an `npm audit` gate; committed lockfile + `npm ci`; sane `SECURITY.md` and `.gitignore`; verifier session consumes nonce synchronously (race-safe); express default 100 KB body limit; no CORS wildcards; mobile keys hardware-backed (Secure Enclave / AndroidKeystore + StrongBox) with no WebView or deep-link surface; existing tests already cover several negatives (wrong nonce, forged keys, untrusted/tampered JAR, revoked status, `http://` SSRF).

**[demo-accepted] limitations not counted as findings:** software/extractable keys (WSCD), in-memory state, cleartext HTTP to localhost demo services, fictional PID data, missing `redirect_uri` flow.

---

*This audit is a point-in-time review of the working tree on 2026-06-10. Line numbers refer to that state.*
