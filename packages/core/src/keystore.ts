/**
 * Key-storage abstraction (WSCD boundary).
 *
 * A production EUDI wallet must keep private keys in a **WSCD** — a Wallet Secure Cryptographic
 * Device (secure element / TEE / HSM) — so the key material never leaves hardware and signing
 * happens inside it. This module models that boundary: callers obtain a `JwsSigner` that can sign
 * but **cannot export the private key**. The demo ships a `SoftwareKeyStore` (keys in memory);
 * a real wallet swaps in a hardware-backed implementation behind the same interface.
 */
import { SignJWT, importJWK, type JWK } from "jose";
import { randomUUID, sign as nodeSign, type KeyObject } from "node:crypto";
import { ALG } from "./types.js";
import { generateP256KeyPair } from "./crypto.js";

/** A signing capability bound to one key. The private key is never exposed. */
export interface JwsSigner {
  /** Public key to bind into a credential (`cnf` for SD-JWT VC, `deviceKey` for mdoc). */
  readonly publicJwk: JWK;
  /** Sign a compact JWS (used for KB-JWT, OpenID4VCI proof, etc.). */
  signJwt(protectedHeader: Record<string, unknown>, payload: Record<string, unknown>): Promise<string>;
  /** Sign raw bytes, returning a raw ES256 r||s signature (used for COSE/mdoc). */
  signRaw(data: Uint8Array): Promise<Uint8Array>;
}

export interface ManagedKey {
  keyId: string;
  publicJwk: JWK;
}

export interface WalletKeyStore {
  generateKey(): Promise<ManagedKey>;
  getPublicJwk(keyId: string): Promise<JWK>;
  getSigner(keyId: string): JwsSigner;
}

/** Build a software-backed signer from a private JWK (also used to normalise `JWK | JwsSigner`). */
export function softwareSigner(privateJwk: JWK, publicJwk: JWK): JwsSigner {
  return {
    publicJwk,
    async signJwt(protectedHeader, payload) {
      const key = (await importJWK(privateJwk, ALG)) as KeyObject;
      return new SignJWT(payload).setProtectedHeader(protectedHeader as never).sign(key);
    },
    async signRaw(data) {
      const key = (await importJWK(privateJwk, ALG)) as KeyObject;
      return nodeSign("sha256", data, { key, dsaEncoding: "ieee-p1363" });
    },
  };
}

/**
 * Normalise a `JWK | JwsSigner` to a `JwsSigner`. When given a private JWK we derive the public
 * key from it (x/y/crv). Lets credential APIs accept either a raw key (tests) or a WSCD-backed
 * signer (wallet) without overloads.
 */
export function asSigner(holder: JWK | JwsSigner): JwsSigner {
  if (typeof (holder as JwsSigner).signJwt === "function") return holder as JwsSigner;
  const jwk = holder as JWK;
  const pub: JWK = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, alg: ALG };
  return softwareSigner(jwk, pub);
}

/** In-memory key store. DEMO ONLY — a real wallet uses a WSCD (secure element / TEE / HSM). */
export class SoftwareKeyStore implements WalletKeyStore {
  private keys = new Map<string, { priv: JWK; pub: JWK }>();

  async generateKey(): Promise<ManagedKey> {
    const { privateJwk, publicJwk } = await generateP256KeyPair();
    const keyId = randomUUID();
    this.keys.set(keyId, { priv: privateJwk, pub: publicJwk });
    return { keyId, publicJwk };
  }

  async getPublicJwk(keyId: string): Promise<JWK> {
    const k = this.keys.get(keyId);
    if (!k) throw new Error(`unknown keyId: ${keyId}`);
    return k.pub;
  }

  getSigner(keyId: string): JwsSigner {
    const k = this.keys.get(keyId);
    if (!k) throw new Error(`unknown keyId: ${keyId}`);
    return softwareSigner(k.priv, k.pub);
  }
}
