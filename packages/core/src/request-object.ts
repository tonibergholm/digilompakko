/**
 * OpenID4VP signed request objects (JAR — RFC 9101).
 *
 * Without this, a wallet can't tell whether an Authorization Request genuinely came from the
 * Relying Party it claims to be. The verifier signs its request as a JWT; the wallet verifies the
 * signature against the RP's published key before disclosing anything. HAIP requires signed
 * request objects for high assurance.
 */
import { SignJWT, jwtVerify, importJWK, type JWK } from "jose";
import { ALG } from "./types.js";
import { Oid4vcError } from "./errors.js";

const REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";

/**
 * Verifier side: sign an Authorization Request object.
 *
 * Sets a 120-second expiry — HAIP §5.3 requires short-lived request objects so a captured JAR
 * cannot be replayed by an attacker to a different wallet session.
 */
export async function signRequestObject(privateJwk: JWK, claims: Record<string, unknown>): Promise<string> {
  const key = await importJWK(privateJwk, ALG);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: ALG, typ: REQUEST_OBJECT_TYP })
    .setIssuedAt()
    .setExpirationTime("120s")
    .sign(key);
}

/**
 * Wallet side: verify a signed request object and return its claims. Throws on bad signature.
 *
 * @internal Use verifyPresentationRequest for full high-assurance verification. This function
 *           performs only a signature check without aud/allowlist binding and is therefore
 *           NOT sufficient for production use.
 */
export async function verifyRequestObject(jwt: string, publicJwk: JWK): Promise<Record<string, unknown>> {
  const key = await importJWK(publicJwk, ALG);
  try {
    // HAIP §2.1: only ES256 is permitted.
    const { payload } = await jwtVerify(jwt, key, { typ: REQUEST_OBJECT_TYP, algorithms: ["ES256"] });
    return payload as Record<string, unknown>;
  } catch (e) {
    throw new Oid4vcError("invalid_request", `request object signature invalid: ${(e as Error).message}`);
  }
}

/**
 * Wallet side: full high-assurance verification of a signed OpenID4VP request object (JAR).
 *
 * Enforces the four properties required by RFC 9101 §4 + HAIP:
 *   1. client_id must map to a key in `trustedRps` — key is NOT derived from attacker-controlled
 *      JWT claims or URLs (HIGH-1 fix: eliminates the SSRF / key-confusion vector).
 *   2. typ == "oauth-authz-req+jwt"
 *   3. exp present and not expired (120-second window set by the verifier)
 *   4. aud == opts.expectedAudience (this wallet's own identifier)
 *
 * @param jwt            Compact JAR from the verifier's request endpoint.
 * @param trustedRps     Map of known client_id → pre-loaded public JWK.  The caller is responsible
 *                       for fetching these keys from a trusted endpoint BEFORE calling this function.
 * @param opts.expectedAudience  The wallet's own identifier (shared with the verifier out-of-band).
 * @param opts.now       Seconds-since-epoch override (for deterministic tests only).
 */
export async function verifyPresentationRequest(
  jwt: string,
  trustedRps: Map<string, JWK>,
  opts: { expectedAudience: string; now?: number },
): Promise<Record<string, unknown>> {
  // Decode payload WITHOUT trusting it — we need client_id to look up the key.
  const [, rawPayload] = jwt.split(".");
  if (!rawPayload) throw new Oid4vcError("invalid_request", "malformed request object JWT");
  let peeked: Record<string, unknown>;
  try {
    peeked = JSON.parse(Buffer.from(rawPayload, "base64url").toString()) as Record<string, unknown>;
  } catch {
    throw new Oid4vcError("invalid_request", "request object payload is not valid JSON");
  }
  const clientId = peeked.client_id;
  if (typeof clientId !== "string") {
    throw new Oid4vcError("invalid_request", "request object missing client_id");
  }

  // Trust gate: reject any client_id not in the pre-configured allowlist.
  const rpJwk = trustedRps.get(clientId);
  if (!rpJwk) {
    throw new Oid4vcError("access_denied", `untrusted verifier: ${clientId}`, 403);
  }
  const key = await importJWK(rpJwk, ALG);

  const verifyOpts: { typ: string; audience: string; algorithms: string[]; currentDate?: Date } = {
    typ: REQUEST_OBJECT_TYP,
    audience: opts.expectedAudience,
    // HAIP §2.1: only ES256 is permitted.
    algorithms: ["ES256"],
  };
  if (opts.now !== undefined) {
    verifyOpts.currentDate = new Date(opts.now * 1000);
  }

  try {
    const { payload } = await jwtVerify(jwt, key, verifyOpts);
    return payload as Record<string, unknown>;
  } catch (e) {
    throw new Oid4vcError("invalid_request", `request object verification failed: ${(e as Error).message}`);
  }
}
