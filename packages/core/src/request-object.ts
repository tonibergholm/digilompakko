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

/** Verifier side: sign an Authorization Request object. */
export async function signRequestObject(privateJwk: JWK, claims: Record<string, unknown>): Promise<string> {
  const key = await importJWK(privateJwk, ALG);
  return new SignJWT(claims).setProtectedHeader({ alg: ALG, typ: REQUEST_OBJECT_TYP }).setIssuedAt().sign(key);
}

/** Wallet side: verify a signed request object and return its claims. Throws on bad signature. */
export async function verifyRequestObject(jwt: string, publicJwk: JWK): Promise<Record<string, unknown>> {
  const key = await importJWK(publicJwk, ALG);
  try {
    const { payload } = await jwtVerify(jwt, key, { typ: REQUEST_OBJECT_TYP });
    return payload as Record<string, unknown>;
  } catch (e) {
    throw new Oid4vcError("invalid_request", `request object signature invalid: ${(e as Error).message}`);
  }
}
