/**
 * IETF Token Status List (draft-ietf-oauth-status-list).
 *
 * A Status List is a bitstring: each credential is assigned an index, and the bits at that
 * index encode its status (here 1 bit/entry: 0 = VALID, 1 = INVALID/REVOKED). The list is
 * DEFLATE-compressed and base64url-encoded, then published inside a signed "Status List Token"
 * (a JWT with typ `statuslist+jwt`). A credential references it via:
 *
 *   "status": { "status_list": { "idx": <n>, "uri": "<status-list-token-url>" } }
 *
 * The verifier fetches the token, verifies the issuer signature, and reads the bit at `idx`.
 */
import { SignJWT, jwtVerify, importJWK, type JWK } from "jose";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import { ALG } from "./types.js";
import { Oid4vcError } from "./errors.js";

export const STATUS_VALID = 0;
export const STATUS_INVALID = 1; // revoked or suspended

/** Reference embedded in a credential pointing to its status entry. */
export interface StatusReference {
  status_list: { idx: number; uri: string };
}

/** A growable 1-bit-per-entry status list. */
export class StatusList {
  private bytes: Uint8Array;
  constructor(public readonly size: number = 1024) {
    this.bytes = new Uint8Array(Math.ceil(size / 8));
  }

  get(idx: number): number {
    this.assertInRange(idx);
    return (this.bytes[idx >> 3] >> (idx & 7)) & 1;
  }

  set(idx: number, value: 0 | 1): void {
    this.assertInRange(idx);
    const byte = idx >> 3;
    const bit = idx & 7;
    if (value) this.bytes[byte] |= 1 << bit;
    else this.bytes[byte] &= ~(1 << bit);
  }

  private assertInRange(idx: number): void {
    if (idx < 0 || idx >= this.size) throw new Oid4vcError("invalid_request", `status index out of range: ${idx}`);
  }

  /** DEFLATE + base64url, as required for the `lst` field. */
  encode(): string {
    return Buffer.from(deflateRawSync(Buffer.from(this.bytes))).toString("base64url");
  }

  static decodeBytes(lst: string): Uint8Array {
    return new Uint8Array(inflateRawSync(Buffer.from(lst, "base64url")));
  }
}

/** Build a signed Status List Token (JWT, typ `statuslist+jwt`). */
export async function buildStatusListToken(
  issuerPrivateJwk: JWK,
  issuer: string,
  subjectUri: string,
  list: StatusList,
): Promise<string> {
  const key = await importJWK(issuerPrivateJwk, ALG);
  return new SignJWT({
    sub: subjectUri,
    status_list: { bits: 1, lst: list.encode() },
  })
    .setProtectedHeader({ alg: ALG, typ: "statuslist+jwt" })
    .setIssuer(issuer)
    .setIssuedAt()
    .sign(key);
}

/**
 * Verify a Status List Token and read the status at `idx`.
 *
 * Validation performed (draft-ietf-oauth-status-list §5):
 *   - Signature against `issuerPublicJwk` (ES256, typ `statuslist+jwt`)
 *   - `iss` == opts.expectedIssuer — prevents cross-issuer token substitution
 *   - `sub` == opts.expectedUri   — ensures the token was issued for this URI
 *   - `bits` == 1                 — this implementation only handles 1-bit entries
 *   - `idx` in range              — prevents out-of-bounds reads
 *
 * Throws Oid4vcError on any failure.
 */
export async function readStatus(
  statusListToken: string,
  idx: number,
  issuerPublicJwk: JWK,
  opts: { expectedIssuer: string; expectedUri: string },
): Promise<number> {
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(issuerPublicJwk, ALG);
    ({ payload } = await jwtVerify(statusListToken, key, {
      typ: "statuslist+jwt",
      // draft-ietf-oauth-status-list §5.1: `iss` MUST match the credential issuer.
      issuer: opts.expectedIssuer,
    }) as { payload: Record<string, unknown> });
  } catch (e) {
    throw new Oid4vcError("status_unavailable", `status list token invalid: ${(e as Error).message}`);
  }

  // draft-ietf-oauth-status-list §5.1: `sub` MUST equal the URI the token was fetched from.
  // This prevents an attacker from serving a valid token for a different status list.
  if (payload.sub !== opts.expectedUri) {
    throw new Oid4vcError(
      "status_unavailable",
      `status list token sub mismatch: expected ${opts.expectedUri}, got ${String(payload.sub)}`,
    );
  }

  const sl = payload.status_list as { bits?: number; lst?: string } | undefined;
  if (!sl?.lst) throw new Oid4vcError("status_unavailable", "status list token missing status_list.lst");
  // Only 1-bit-per-entry lists are supported; a different `bits` value means the list uses a
  // different encoding and reading it with 1-bit arithmetic would silently return wrong results.
  if (sl.bits !== 1) {
    throw new Oid4vcError("status_unavailable", `unsupported status_list bits value: ${sl.bits} (expected 1)`);
  }

  const bytes = StatusList.decodeBytes(sl.lst);
  const byte = idx >> 3;
  if (byte >= bytes.length) throw new Oid4vcError("invalid_request", `status index out of range: ${idx}`);
  return (bytes[byte] >> (idx & 7)) & 1;
}
