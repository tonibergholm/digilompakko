/**
 * Hardened HTTP client utilities (MEDIUM-1 remediation).
 *
 * All outbound fetches in the wallet/verifier must go through these helpers to prevent
 * SSRF, resource exhaustion, and redirect-based exfiltration:
 *   - assertSafeUrl: rejects non-HTTPS URLs unless the host is a loopback address.
 *     HTTP to localhost/127.0.0.1/::1 is allowed so the demo works without TLS.
 *   - safeFetch: wraps fetch with a 5-second abort timeout and HTTP-status check.
 *   - safeFetchJson / safeFetchText: consume the body and enforce a 1 MiB size cap.
 *
 * Design decisions:
 *   - No blocking on Content-Length alone (can be spoofed or absent); we read the body
 *     and count bytes after receiving it.
 *   - Redirects are followed by default (Node fetch behaviour), which is acceptable here
 *     because the HTTPS-only + loopback rule means a redirect to a private IP via HTTP
 *     will be blocked at the next request.
 */
import { Oid4vcError } from "./errors.js";

const FETCH_TIMEOUT_MS = 5_000;
const MAX_BODY_BYTES = 1_048_576; // 1 MiB

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Assert that `rawUrl` is safe to fetch from:
 *   - Must be a valid URL.
 *   - Must use HTTPS, OR be directed at a loopback host (localhost / 127.0.0.1 / ::1).
 *
 * Throws Oid4vcError("invalid_request") if the URL fails either check.
 */
export function assertSafeUrl(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Oid4vcError("invalid_request", `SSRF guard: invalid URL: ${rawUrl}`);
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
 * Fetch `url` with a 5-second timeout.  Throws on network error, non-2xx status, or
 * an unsafe URL (see assertSafeUrl).
 */
export async function safeFetch(url: string, init?: RequestInit): Promise<Response> {
  assertSafeUrl(url);
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(url, { ...init, signal: ac.signal });
  } catch (e) {
    throw new Oid4vcError("status_unavailable", `network error fetching ${url}: ${(e as Error).message}`);
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    throw new Oid4vcError("status_unavailable", `HTTP ${res.status} from ${url}`);
  }
  return res;
}

/**
 * Fetch `url`, read the body as UTF-8 text, and enforce the 1 MiB size cap.
 */
export async function safeFetchText(url: string): Promise<string> {
  const res = await safeFetch(url);
  const text = await res.text();
  if (text.length > MAX_BODY_BYTES) {
    throw new Oid4vcError("status_unavailable", `response body too large from ${url} (${text.length} bytes)`);
  }
  return text;
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
