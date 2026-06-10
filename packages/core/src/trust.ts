/**
 * Trust resolution.
 *
 * In the real EUDI ecosystem, a verifier decides whether to trust an issuer by consulting the
 * EU/Member-State **Trusted Lists** (and the Registrar). This module abstracts that decision
 * behind a `TrustResolver` so the demo can ship a simple allow-list today and swap in a real
 * Trusted List client later without touching the verifier.
 */
import type { JWK } from "jose";
import { Oid4vcError } from "./errors.js";
import { safeFetchJson } from "./http.js";

export interface TrustResolver {
  /** Return the issuer's signing key if the issuer is trusted; throw otherwise. */
  resolveIssuerKey(issuer: string): Promise<JWK>;
}

/**
 * Demo resolver: trusts only issuers on an explicit allow-list, and fetches their signing key
 * from the issuer's published OpenID4VCI metadata (`/.well-known/openid-credential-issuer`).
 * Keys are cached after first resolution.
 */
/** Cache entries expire after 5 minutes so stale keys are refreshed on rotation. */
const TRUST_CACHE_TTL_MS = 5 * 60 * 1000;

export class StaticTrustResolver implements TrustResolver {
  private cache = new Map<string, { key: JWK; cachedAt: number }>();
  constructor(private readonly trustedIssuers: string[]) {}

  async resolveIssuerKey(issuer: string): Promise<JWK> {
    if (!this.trustedIssuers.includes(issuer)) {
      throw new Oid4vcError("untrusted_issuer", `issuer not on trusted list: ${issuer}`, 403);
    }
    const cached = this.cache.get(issuer);
    if (cached && Date.now() - cached.cachedAt < TRUST_CACHE_TTL_MS) return cached.key;

    let key: JWK | undefined;
    try {
      const meta = await safeFetchJson<{ jwks?: { keys?: JWK[] } }>(`${issuer}/.well-known/openid-credential-issuer`);
      key = meta?.jwks?.keys?.[0];
    } catch (e) {
      throw new Oid4vcError("untrusted_issuer", `cannot fetch issuer metadata: ${(e as Error).message}`, 502);
    }
    if (!key) throw new Oid4vcError("untrusted_issuer", "issuer metadata has no JWKS key");

    // HAIP §2.1: only EC P-256 keys are permitted; reject anything else before caching.
    if (key.kty !== "EC" || key.crv !== "P-256") {
      throw new Oid4vcError("untrusted_issuer", "issuer JWKS key must be EC P-256");
    }

    this.cache.set(issuer, { key, cachedAt: Date.now() });
    return key;
  }
}
