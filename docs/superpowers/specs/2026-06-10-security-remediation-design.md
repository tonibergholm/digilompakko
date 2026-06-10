# Security Remediation Design — Digilompakko

**Date:** 2026-06-10
**Scope:** All 22 findings from `SECURITY_AUDIT.md` (P0–P3)
**Approach:** Concern-grouped PRs; HTTP layer redesigned first to eliminate the raw-fetch bypass as a side-effect; architecture deep-dives on HTTP and wallet trust; everything else in contained follow-on PRs.

---

## Sprint structure — 8 PRs

| PR | Label | Findings | What changes |
|----|-------|----------|--------------|
| 1 | `fix/http-ssrf-hardening` | #2 #7 #9 | Redesign `packages/core/src/http.ts`; route all egress |
| 2 | `fix/wallet-trust-and-response-uri` | #5 #6 | `response_uri` origin check; `URL.origin` allowlist |
| 3 | `fix/admin-auth-and-result-pii` | #3 #13 #10 | Admin bearer token; resultToken split; TTL sweeps |
| 4 | `fix/token-lifecycle` | #4 #11 #12 | Status-list `exp`; pre-auth TTL; auth-code client binding |
| 5 | `fix/wallet-xss-and-headers` | #1 | DOM construction; security headers middleware |
| 6 | `fix/mdoc-correctness` | #8 #17 | docType binding; validFrom; CBOR size gate |
| 7 | `fix/defense-in-depth` | #14 #15 #16 #18 #19 #20 #21 | Algorithm pinning; race; KB-JWT; trust cache; misc |
| 8 | `test/adversarial-coverage` | #22 | Negative test suite |

Each PR is a standalone `fix/` or `test/` branch off `main`, squash-merged, with CI green before merge. PRs 1–7 should merge in order (PR 1 eliminates the raw-fetch bypasses the others rely on). PR 8 lands last so assertions exercise the new code paths.

---

## PR 1 — HTTP SSRF hardening (`http.ts` redesign)

### Why a redesign, not a patch

Current `assertSafeUrl` permits `https://10.0.0.1/`, `https://169.254.169.254/`, ULA/link-local IPv6. `safeFetch` uses default redirect following — the guard is applied to the initial URL only; a `302 → https://10.0.0.1/` bypasses it entirely. `safeFetchText` calls `await res.text()` (materialises the full body in memory) then counts UTF-16 code units rather than bytes.

Patching each symptom individually leaves the next caller free to introduce the same bugs. A redesigned API that is hard to misuse is the right approach.

### New API shape

```typescript
// Block private/link-local/ULA/metadata ranges AND non-HTTPS for non-loopback.
export function assertSafeUrl(rawUrl: string): URL

// 5-second timeout, redirect: "manual", re-validates Location per hop (max 5 hops).
export async function safeFetch(url: string, init?: RequestInit): Promise<Response>

// Streams body, aborts at MAX_BODY_BYTES bytes (not characters), decodes only on success.
export async function safeFetchText(url: string): Promise<string>

// Parses the text result as JSON.
export async function safeFetchJson<T>(url: string): Promise<T>
```

### Blocked IP ranges

`assertSafeUrl` must reject (regardless of protocol) any URL whose host falls in:

| Range | Description |
|-------|-------------|
| `10.0.0.0/8` | RFC 1918 private |
| `172.16.0.0/12` | RFC 1918 private |
| `192.168.0.0/16` | RFC 1918 private |
| `169.254.0.0/16` | Link-local / metadata (AWS IMDSv1) |
| `fc00::/7` | ULA IPv6 |
| `fe80::/10` | Link-local IPv6 |

Exception: `localhost`, `127.0.0.1`, `[::1]` remain allowed so the demo works without TLS. This is a syntax/hostname guard; DNS rebinding is a separate concern noted in ROADMAP.

### Redirect handling

```
redirect: "manual"  →  if status 3xx, extract Location header
                    →  assertSafeUrl(location) per hop
                    →  re-fetch with same init up to 5 hops
                    →  throw Oid4vcError on hop limit or unsafe Location
```

`safeFetch` implements this loop internally; callers see no change.

### Streaming body cap

```typescript
const reader = res.body!.getReader();
const chunks: Uint8Array[] = [];
let total = 0;
while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  total += value.byteLength;          // bytes, not UTF-16 units
  if (total > MAX_BODY_BYTES) {
    await reader.cancel();
    throw new Oid4vcError("status_unavailable", `response body too large from ${url}`);
  }
  chunks.push(value);
}
return Buffer.concat(chunks).toString("utf8");
```

### Migration of raw `fetch` calls

All raw `fetch` calls in `apps/wallet/src/wallet.ts` (lines 95, 119–123, 165) and `apps/wallet/src/server.ts` (lines 27, 38, 66) must be routed through `safeFetch` or `postJson` (which already uses `safeFetch`). The `wallet.ts:143-147` POST to `response_uri` gets the origin check in PR 2 first, then routes through `safeFetch`.

---

## PR 2 — Wallet trust model (`response_uri` + allowlist)

### Finding #5 — `vp_token` posted to unvalidated `response_uri`

`wallet.ts:143-147` posts PII-bearing `vp_token` to whatever `response_uri` the request object names, with no check that it belongs to the verified `client_id`.

Fix: before POSTing, enforce:
```typescript
if (new URL(request.response_uri).origin !== new URL(request.client_id).origin) {
  throw new Oid4vcError("invalid_request", "response_uri origin does not match client_id origin");
}
```
Then POST via `safeFetch`.

### Finding #6 — verifier trust uses `startsWith`

`wallet.ts:177`:
```typescript
// before (vulnerable):
const trustedOrigin = this.config.trustedVerifierOrigins.find((o) => clientId.startsWith(o));

// after (fixed):
const clientOrigin = new URL(clientId).origin;
const trustedOrigin = this.config.trustedVerifierOrigins.find(
  (o) => new URL(o).origin === clientOrigin
);
```

`http://localhost:4002.evil.com` no longer passes when the allowlist contains `http://localhost:4002`.

---

## PR 3 — Admin auth + presentation PII binding

### Finding #3 — Unauthenticated admin endpoints

`POST /admin/revoke` and `GET /admin/issued` have no authentication. Any network client can revoke any credential or enumerate PII.

Fix: add middleware that checks `Authorization: Bearer <ADMIN_TOKEN>` against `process.env.ADMIN_TOKEN`. If `ADMIN_TOKEN` is unset, the server throws at startup. Both admin endpoints use this middleware.

### Finding #13 — Presentation result readable by anyone with session id

The wallet receives `request_uri` containing session `id`. `GET /presentation/result/:id` returns full PII to anyone who knows `id`. Since `id` must travel to the wallet (embedded in `request_uri`), it cannot simultaneously be a secret.

Fix: separate the wallet-facing opaque handle from the RP-facing retrieval token.

```typescript
// POST /presentation/request:
const id = randomUUID();           // embedded in request_uri → given to wallet
const resultToken = randomUUID();  // returned to RP → never reaches wallet
sessions.set(id, { ..., resultToken });
res.json({ request_id: id, request_uri: `.../${id}`, result_token: resultToken });

// GET /presentation/result/:resultToken:
app.get("/presentation/result/:resultToken", (req, res) => {
  const session = [...sessions.values()].find(s => s.resultToken === req.params.resultToken);
  // ...
  session.result = undefined; // purge PII after read
});
```

### Finding #10 — Unbounded in-memory maps

`offers`, `parRequests`, `authCodes`, `accessTokens` (issuer) and `sessions` (verifier) grow without bound.

Fix: a `sweepExpired()` function per server, called via `setInterval(sweepExpired, 60_000)`. Entries older than their respective TTL are deleted. Additionally, cap each map at `MAX_MAP_SIZE = 10_000` entries — reject new entries with `429` if at cap.

---

## PR 4 — Token lifecycle

### Finding #4 — Status list token never expires

`buildStatusListToken` at `status-list.ts:74` calls `.setIssuedAt()` with no `.setExpirationTime()`.

Fix: add `ttlSeconds: number = 3600` parameter:
```typescript
.setIssuedAt()
.setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
```

`jose`'s `jwtVerify` already enforces `exp` by default; make this explicit in the JSDoc. Add a note that callers should not cache the token beyond its remaining TTL.

### Finding #11 — Pre-authorized code has no TTL

`offers.set(preAuthCode, { configId })` stores no timestamp.

Fix: stamp `createdAt: Date.now()` on offer creation. At `/token` redemption:
```typescript
const PRE_AUTH_CODE_TTL_MS = 30_000;
if (Date.now() - (pending.createdAt ?? 0) > PRE_AUTH_CODE_TTL_MS) {
  offers.delete(code);
  throw new Oid4vcError("invalid_grant", "pre-authorized_code expired");
}
```

### Finding #12 — Auth code not bound to `client_id`

Fix:
1. Thread `clientId` into the auth code entry: `{ codeChallenge, clientId: par.clientId, pending, createdAt }`.
2. At the token endpoint, assert: `if (req.body?.client_id !== entry.clientId) throw new Oid4vcError("invalid_grant", "client_id mismatch")`.

---

## PR 5 — Wallet XSS + security headers

### Finding #1 — XSS via innerHTML

`apps/wallet/src/server.ts:125-126` assigns `r.vct` and `r.error` (issuer/verifier-controlled) via `innerHTML` string concatenation.

Fix: replace with DOM construction:
```javascript
function setText(el, cls, msg) {
  const span = document.createElement("span");
  span.className = cls;
  span.textContent = msg;   // never interpreted as markup
  el.replaceChildren(span);
}
```

### Security headers

Add a `securityHeaders` middleware to `apps/wallet/src/server.ts` (wallet only — issuer and verifier serve no HTML):

```typescript
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'"
  );
  next();
});
```

`unsafe-inline` is required for the inline `<script>` block; acceptable here since the XSS is eliminated at the DOM level. Extracting the script to a static file would allow removing `unsafe-inline` — noted as a ROADMAP item.

---

## PR 6 — mdoc correctness

### Finding #8 — docType not bound; validFrom unchecked

In `verifyMdocPresentation` (`mdoc.ts:219`):

1. After recovering the MSO (line 240), immediately assert:
   ```typescript
   if (mso.get("docType") !== docType) errors.push("docType mismatch between Document and MSO");
   ```
   This check must occur before claim extraction.

2. Add `validFrom` check alongside the existing `validUntil` check:
   ```typescript
   if (validity.get("validFrom")! > Math.floor(Date.now() / 1000)) errors.push("mdoc not yet valid (validFrom)");
   ```

### Finding #17 — CBOR decoded before signature check, no size bound

Add a byte-length gate before every `dec()` call on attacker-supplied input:

```typescript
const MAX_CBOR_BYTES = 1_048_576;
function safeDec(b: Uint8Array): unknown {
  if (b.byteLength > MAX_CBOR_BYTES) {
    throw new Oid4vcError("invalid_presentation", `CBOR too large: ${b.byteLength} bytes`);
  }
  return dec(b);
}
```

Replace `dec(Buffer.from(deviceResponseB64, "base64url"))` at line 231 and the inner MSO decode at line 240 with `safeDec(...)`.

Full strict-mode duplicate-key rejection requires a CBOR library with explicit support; documented as a ROADMAP item.

---

## PR 7 — Defense-in-depth

### #15 — Algorithm pinning

Add `algorithms: ["ES256"]` to every `jwtVerify` options object:
- `sd-jwt.ts:135` (issuer signature)
- `sd-jwt.ts:164` (KB-JWT)
- `status-list.ts:99` (status list token)
- `request-object.ts:34` (verifyRequestObject)
- `request-object.ts:92` (verifyPresentationRequest)
- `issuer/server.ts:247` (proof-of-possession)

For COSE: in `coseSign1Verify` (`mdoc.ts:74`), decode the protected header and assert `protectedHdr.get(1) === -7` (ES256).

### #16 — Access-token double-spend race

`issuer/server.ts:226-275`: Move `accessTokens.delete(accessToken)` to immediately after the TTL check, before the first `await`. This mirrors the `session.consumed = true` pattern already used in the verifier.

### #18 — KB-JWT freshness + `nbf`

In `verifyPresentation` (`sd-jwt.ts:164-177`):

```typescript
const KB_JWT_MAX_AGE_S = 300;
const now = Math.floor(Date.now() / 1000);

// After jwtVerify of kbJwt:
if (typeof kb.iat !== "number" || now - kb.iat > KB_JWT_MAX_AGE_S) {
  errors.push("KB-JWT too old (replay risk)");
}

// After jwtVerify of the issuer JWS:
if (payload.nbf && (payload.nbf as number) > now) {
  errors.push("Credential not yet valid (nbf).");
}
```

### #19 — Trust resolver key validation + cache TTL

`trust.ts:36-42`:
- Validate: `if (key.kty !== "EC" || key.crv !== "P-256") throw new Oid4vcError("untrusted_issuer", "unexpected key type")`.
- Change cache to `Map<string, { key: JWK; cachedAt: number }>`. Add `TRUST_CACHE_TTL_MS = 5 * 60 * 1000`. Check age before returning; if stale, re-fetch.

### #20 — Demote `verifyRequestObject`

Remove `verifyRequestObject` from `packages/core/src/index.ts`. Add `/** @internal */` JSDoc. Confirm via `grep -r "verifyRequestObject" apps/` that no app imports it directly.

### #21 — Miscellaneous one-liners

- **Negative status index** (`status-list.ts`): add `if (idx < 0) throw new Oid4vcError("invalid_request", \`negative status index: ${idx}\`)` in `readStatus` before byte arithmetic.
- **`_sd_alg` ignored** (`sd-jwt.ts`): after recovering `payload`, add `if (payload._sd_alg && payload._sd_alg !== "sha-256") errors.push("unsupported _sd_alg")`.
- **PKCE timing** (`pkce.ts`): replace `===` with `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`.
- **Demo nonce** (`scripts/demo.ts:32`): replace `Math.random()` with `randomUUID()` from `node:crypto`.

### #14 — shell-quote advisory

Run `npm audit fix` targeting the `concurrently` transitive. Add `npm audit --audit-level=high` step to `.woodpecker.yml` to match GitHub CI.

---

## PR 8 — Adversarial test coverage

All tests live in `packages/core` under `npm test` (node:test). No service startup required.

| Test | Finding | What it proves |
|------|---------|----------------|
| Status-list token with `exp` in past → `readStatus` throws | #4 | Stale-list replay blocked |
| Status-list token with `exp` in future → passes | #4 | Baseline still works |
| `assertSafeUrl("https://10.0.0.1/")` → throws | #2 | Private IP blocked |
| `assertSafeUrl("https://169.254.169.254/")` → throws | #2 | Metadata endpoint blocked |
| `assertSafeUrl("https://172.16.0.1/")` → throws | #2 | RFC 1918 blocked |
| `assertSafeUrl("https://fc00::1/")` → throws | #2 | ULA IPv6 blocked |
| Redirect `302 → https://10.0.0.1/` → throws | #2 | Redirect bypass blocked |
| 2 MiB response stream → `safeFetchText` aborts | #9 | Memory DoS blocked |
| mdoc with byte-flipped `elementValue` → digest mismatch | #8 | Tamper detection |
| mdoc with wrong `docType` in Document → docType mismatch | #8 | Doc-type confusion blocked |
| mdoc with `validFrom = now + 1000` → not yet valid | #8 | Future-dated credential blocked |
| SD-JWT with extra disclosure not in `_sd` → error | #22 | Disclosure addition blocked |
| SD-JWT with `exp` in past → `Credential expired` | #22 | Expiry enforced |
| JWT signed with RS256 → `jwtVerify` (algorithms: ES256) throws | #15 | Alg confusion blocked |
| CBOR bytes > `MAX_CBOR_BYTES` → throws before decode | #17 | CBOR bomb blocked |
| `readStatus(token, -1, ...)` → throws | #21 | Negative index blocked |
| KB-JWT with `iat = now - 400` → `KB-JWT too old` | #18 | Stale KB-JWT blocked |

---

## Cross-cutting constraints

- Every PR must pass `npm run build` (zero TS errors) and `npm test` (green) before merge.
- PRs 1–7 merge in order: PR 1 (HTTP) eliminates raw-fetch bypasses that PRs 2–7 rely on. PRs 2–7 are otherwise independent of each other.
- PR 8 lands after PRs 1–7 so the assertions exercise the new code paths.
- `docs/COMPLIANCE.md` traceability table updates in the same PR as any finding that changes the compliance surface (#4 status-list exp, #3 admin auth, #15 algorithm pinning).
