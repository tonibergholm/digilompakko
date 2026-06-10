/**
 * PKCE (RFC 7636) — required by the OpenID4VCI Authorization Code flow.
 * HAIP mandates the S256 method.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { Oid4vcError } from "./errors.js";

/** Compute the S256 code_challenge for a given code_verifier. */
export function pkceS256Challenge(codeVerifier: string): string {
  return createHash("sha256").update(codeVerifier).digest("base64url");
}

/** Verify a code_verifier against a stored code_challenge. Throws on mismatch. */
export function verifyPkce(codeVerifier: string, codeChallenge: string, method = "S256"): void {
  if (method !== "S256") throw new Oid4vcError("invalid_request", `unsupported PKCE method: ${method}`);
  if (!codeVerifier) throw new Oid4vcError("invalid_request", "missing code_verifier");
  // RFC 7636 §4.6: use constant-time comparison to prevent timing side-channels that could
  // allow an attacker to infer the correct code_challenge one byte at a time.
  const computed = pkceS256Challenge(codeVerifier);
  if (!timingSafeEqual(Buffer.from(computed), Buffer.from(codeChallenge))) {
    throw new Oid4vcError("invalid_grant", "PKCE code_verifier mismatch");
  }
}
