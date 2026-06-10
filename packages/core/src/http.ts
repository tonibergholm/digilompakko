/**
 * Hardened HTTP client utilities (SSRF hardening — findings #2, #7, #9).
 *
 * All outbound fetches in the wallet/verifier must go through these helpers to prevent
 * SSRF, resource exhaustion, and redirect-based exfiltration:
 *   - assertSafeUrl: rejects non-HTTPS URLs unless the host is a loopback address;
 *     additionally rejects RFC 1918 / link-local / ULA private IP ranges even over HTTPS.
 *   - safeFetch: manual redirect loop that re-validates each hop through assertSafeUrl,
 *     with a per-hop 5-second abort timeout.
 *   - safeFetchText: consumes body via a streaming byte counter and enforces a 1 MiB cap.
 *   - safeFetchJson: wraps safeFetchText with JSON.parse.
 *
 * Design decisions:
 *   - Private IPs are blocked regardless of protocol — HTTPS to 10.x is still SSRF.
 *   - Redirects use redirect:"manual" so we inspect the Location header and re-run
 *     assertSafeUrl before following each hop; this closes the redirect-to-private-IP vector.
 *   - Body cap is enforced via a streaming reader, not Content-Length (can be spoofed/absent).
 *   - HTTP to localhost/127.0.0.1/::1 is allowed so the demo works without TLS.
 */
import { Oid4vcError } from "./errors.js";

const FETCH_TIMEOUT_MS = 5_000;
export const MAX_BODY_BYTES = 1_048_576; // 1 MiB
const MAX_REDIRECTS = 5;

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Returns true if `hostname` is an RFC 1918 private IPv4 address or a link-local IPv4 address
 * (169.254.x.x / AWS metadata endpoint).
 */
function isPrivateIPv4(hostname: string): boolean {
  const m = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [, a, b] = m.map(Number);
  if (a === 10) return true;                          // RFC 1918 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true;  // RFC 1918 172.16.0.0/12
  if (a === 192 && b === 168) return true;            // RFC 1918 192.168.0.0/16
  if (a === 169 && b === 254) return true;            // Link-local / metadata
  return false;
}

/**
 * Returns true if `hostname` is a ULA (fc00::/7) or link-local (fe80::/10) IPv6 address.
 * Input may or may not be bracket-wrapped.
 */
function isPrivateIPv6(hostname: string): boolean {
  const h = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  // ULA: fc00::/7 — addresses starting with fc or fd
  if (/^fc/i.test(h) || /^fd/i.test(h)) return true;
  // Link-local: fe80::/10 — fe80..feb (first two hex digits fe, third digit 8-b)
  if (/^fe8/i.test(h) || /^fe9/i.test(h) || /^fea/i.test(h) || /^feb/i.test(h)) return true;
  return false;
}

/**
 * Assert that `rawUrl` is safe to fetch from:
 *   1. Must be a valid URL.
 *   2. Must not be a private/link-local IPv4 or IPv6 address (blocks SSRF even over HTTPS).
 *   3. Must use HTTPS, OR be directed at a loopback host (localhost / 127.0.0.1 / ::1).
 *
 * Throws Oid4vcError("invalid_request") if any check fails.
 */
export function assertSafeUrl(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Oid4vcError("invalid_request", `SSRF guard: invalid URL: ${rawUrl}`);
  }

  // Block private/link-local IP ranges even over HTTPS — SSRF is not protocol-dependent.
  if (isPrivateIPv4(url.hostname) || isPrivateIPv6(url.hostname)) {
    throw new Oid4vcError(
      "invalid_request",
      `SSRF guard: private/link-local IP address rejected: ${url.hostname}`,
    );
  }

  const isLoopback = LOOPBACK_HOSTS.has(url.hostname);
  if (!isLoopback && url.protocol !== "https:") {
    throw new Oid4vcError(
      "invalid_request",
      `SSRF guard: HTTPS required for non-loopback host (got ${url.protocol}//${url.hostname})`,
    );
  }
  return url;
}

/**
 * Fetch `url` with a 5-second timeout per hop.  Follows redirects manually so each hop
 * is re-validated through assertSafeUrl — this prevents redirect-to-private-IP attacks.
 *
 * Throws on network error, non-2xx status, or an unsafe URL (see assertSafeUrl).
 */
export async function safeFetch(url: string, init?: RequestInit): Promise<Response> {
  assertSafeUrl(url);
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let res: Response;
    try {
      res = await fetch(current, { ...init, redirect: "manual", signal: controller.signal });
    } catch (e) {
      throw new Oid4vcError("status_unavailable", `network error fetching ${current}: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) throw new Oid4vcError("invalid_request", "redirect with no Location header");
      const resolved = new URL(location, current).toString();
      // Re-validate each redirect hop — closes the redirect-to-private-IP vector (#2).
      assertSafeUrl(resolved);
      current = resolved;
      continue;
    }
    if (!res.ok) {
      throw new Oid4vcError("status_unavailable", `HTTP ${res.status} from ${current}`);
    }
    return res;
  }
  throw new Oid4vcError("invalid_request", `too many redirects (max ${MAX_REDIRECTS})`);
}

/**
 * Fetch `url`, read the body as UTF-8 text via a streaming byte counter, and enforce
 * the 1 MiB size cap.  Throws if the body exceeds MAX_BODY_BYTES.
 */
export async function safeFetchText(url: string): Promise<string> {
  const res = await safeFetch(url);
  if (!res.body) throw new Oid4vcError("status_unavailable", `empty body from ${url}`);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new Oid4vcError("status_unavailable", `response body too large from ${url}`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Fetch `url`, parse the body as JSON, and enforce the 1 MiB size cap.
 */
export async function safeFetchJson<T>(url: string): Promise<T> {
  const text = await safeFetchText(url);
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Oid4vcError("status_unavailable", `invalid JSON from ${url}`);
  }
}
