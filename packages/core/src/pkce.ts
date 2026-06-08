/**
 * PKCE (RFC 7636) — required by the OpenID4VCI Authorization Code flow.
 * HAIP mandates the S256 method.
 */
import { createHash } from "node:crypto";
import { Oid4vcError } from "./errors.js";

/** Compute the S256 code_challenge for a given code_verifier. */
export function pkceS256Challenge(codeVerifier: string): string {
  return createHash("sha256").update(codeVerifier).digest("base64url");
}

/** Verify a code_verifier against a stored code_challenge. Throws on mismatch. */
export function verifyPkce(codeVerifier: string, codeChallenge: string, method = "S256"): void {
  if (method !== "S256") throw new Oid4vcError("invalid_request", `unsupported PKCE method: ${method}`);
  if (!codeVerifier) throw new Oid4vcError("invalid_request", "missing code_verifier");
  if (pkceS256Challenge(codeVerifier) !== codeChallenge) {
    throw new Oid4vcError("invalid_grant", "PKCE verification failed");
  }
}
