/**
 * Cryptographic primitives for the demo.
 *
 * HAIP 1.0 mandates the ES256 (ECDSA over P-256) suite for wallet ecosystems.
 * We never hand-roll signature crypto: all JWS operations go through `jose`.
 */
import { generateKeyPair, exportJWK, calculateJwkThumbprint, type JWK } from "jose";
import { createHash, randomBytes } from "node:crypto";
import { ALG, CRV, type KeyPair } from "./types.js";

/** Generate a fresh P-256 key pair as JWKs (ES256). */
export async function generateP256KeyPair(): Promise<KeyPair> {
  const { publicKey, privateKey } = await generateKeyPair(ALG, { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  publicJwk.alg = ALG;
  publicJwk.crv = CRV;
  privateJwk.alg = ALG;
  return { publicJwk, privateJwk };
}

/** RFC 7638 JWK thumbprint — stable key identifier. */
export async function jwkThumbprint(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk, "sha256");
}

/** base64url without padding (used for SD-JWT disclosures and digests). */
export function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

/** SHA-256 digest of a string, base64url-encoded — the SD-JWT `_sd` digest. */
export function sha256b64url(input: string): string {
  return createHash("sha256").update(input).digest("base64url");
}

/** Cryptographically random salt for a disclosure (>=128 bits per spec guidance). */
export function newSalt(): string {
  return randomBytes(16).toString("base64url");
}
