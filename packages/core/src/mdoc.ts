/**
 * ISO/IEC 18013-5 mdoc / mDL credential format (CBOR + COSE_Sign1), HAIP `mso_mdoc`.
 *
 * This is a faithful *subset* of 18013-5 sufficient for the issue → present → verify flow,
 * mirroring what `sd-jwt.ts` does for SD-JWT VC but in CBOR/COSE:
 *
 *   - IssuerSigned.nameSpaces : per-namespace array of IssuerSignedItemBytes (tag-24 wrapped),
 *     each carrying a random salt so individual items can be selectively withheld.
 *   - IssuerSigned.issuerAuth : a COSE_Sign1 over the MobileSecurityObject (MSO), which holds
 *     SHA-256 digests of every item plus the holder's deviceKey (holder binding).
 *   - DeviceSigned.deviceAuth : a COSE_Sign1 by the holder over a DeviceAuthentication structure
 *     bound to the verifier's nonce (the mdoc analogue of the SD-JWT Key Binding JWT).
 *
 * Crypto is ES256 / P-256 (HAIP), signatures are raw r||s (COSE), via Node `crypto`.
 * Simplifications vs. full 18013-5 are documented in docs/COMPLIANCE.md.
 */
import { Encoder, Tag } from "cbor-x";
import { importJWK, type JWK } from "jose";
import { createHash, sign as nodeSign, verify as nodeVerify, randomBytes, type KeyObject } from "node:crypto";
import { Oid4vcError } from "./errors.js";
import { asSigner, type JwsSigner } from "./keystore.js";

// Deterministic-ish CBOR: integer map keys preserved (Maps, not objects), no record tables.
const cbor = new Encoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });
const enc = (v: unknown): Buffer => cbor.encode(v) as Buffer;
const dec = (b: Uint8Array): unknown => cbor.decode(b as Buffer);

/** Maximum size of attacker-supplied CBOR input before decode (prevents memory exhaustion). */
export const MAX_CBOR_BYTES = 1_048_576; // 1 MiB

/**
 * Safe CBOR decode: rejects input exceeding MAX_CBOR_BYTES before invoking the decoder.
 * Use on all attacker-controlled input paths (DeviceResponse, MSO payload).
 */
function safeDec(b: Uint8Array): unknown {
  if (b.byteLength > MAX_CBOR_BYTES) {
    throw new Oid4vcError("invalid_presentation", `CBOR too large: ${b.byteLength} bytes`);
  }
  return dec(b);
}

/** Wrap already-encoded bytes as a CBOR tag-24 "encoded data item". */
const tag24 = (bytes: Buffer): Tag => new Tag(bytes, 24);
const sha256 = (b: Buffer): Buffer => createHash("sha256").update(b).digest();

// --- COSE_Key (EC2/P-256) <-> JWK ---------------------------------------------------------
function jwkToCoseKey(jwk: JWK): Map<number, unknown> {
  return new Map<number, unknown>([
    [1, 2], // kty: EC2
    [-1, 1], // crv: P-256
    [-2, Buffer.from(jwk.x!, "base64url")],
    [-3, Buffer.from(jwk.y!, "base64url")],
  ]);
}
function coseKeyToJwk(k: Map<number, unknown>): JWK {
  return {
    kty: "EC",
    crv: "P-256",
    x: Buffer.from(k.get(-2) as Uint8Array).toString("base64url"),
    y: Buffer.from(k.get(-3) as Uint8Array).toString("base64url"),
  };
}

// --- COSE_Sign1 (ES256, detached external_aad empty) ---------------------------------------
const ALG_ES256_HDR = enc(new Map<number, number>([[1, -7]])); // protected header {alg: ES256(-7)}

function sigStructure(payload: Buffer): Buffer {
  // Sig_structure = [ "Signature1", protected, external_aad (empty bstr), payload ]
  return enc(["Signature1", ALG_ES256_HDR, Buffer.alloc(0), payload]);
}

async function coseSign1(privateJwk: JWK, payload: Buffer): Promise<[Buffer, Map<number, unknown>, Buffer, Buffer]> {
  const key = (await importJWK(privateJwk, "ES256")) as KeyObject;
  const signature = nodeSign("sha256", sigStructure(payload), { key, dsaEncoding: "ieee-p1363" });
  // COSE_Sign1 = [ protected (bstr), unprotected (map), payload (bstr), signature (bstr) ]
  return [ALG_ES256_HDR, new Map(), payload, signature];
}

/** COSE_Sign1 where the raw r||s signature comes from a keystore signer (WSCD boundary). */
async function coseSign1Raw(
  signRaw: (d: Uint8Array) => Promise<Uint8Array>,
  payload: Buffer,
): Promise<[Buffer, Map<number, unknown>, Buffer, Buffer]> {
  const signature = Buffer.from(await signRaw(sigStructure(payload)));
  return [ALG_ES256_HDR, new Map(), payload, signature];
}

async function coseSign1Verify(publicJwk: JWK, sign1: unknown[]): Promise<Buffer> {
  const [protectedHdr, , payload, signature] = sign1 as [Buffer, unknown, Buffer, Buffer];
  const key = (await importJWK(publicJwk, "ES256")) as KeyObject;
  const ss = enc(["Signature1", protectedHdr, Buffer.alloc(0), payload]);
  const ok = nodeVerify("sha256", ss, { key, dsaEncoding: "ieee-p1363" }, signature);
  if (!ok) throw new Oid4vcError("invalid_presentation", "COSE_Sign1 signature invalid");
  return Buffer.from(payload);
}

// --- Public types ---------------------------------------------------------------------------
export interface MdocClaims {
  docType: string; // e.g. "org.iso.18013.5.1.mDL"
  namespaces: Record<string, Record<string, unknown>>; // ns -> {element: value}
  validityDays?: number;
  /** Optional Token Status List reference embedded in the MSO for revocation. */
  status?: { idx: number; uri: string };
}

/** Encoded issuer-signed mdoc (base64url of CBOR). Stored by the wallet. */
export interface IssuedMdoc {
  docType: string;
  issuerSigned: string; // base64url(CBOR(IssuerSigned))
}

// --- Issuance -------------------------------------------------------------------------------
export async function issueMdoc(issuerPrivateJwk: JWK, holderPublicJwk: JWK, cred: MdocClaims): Promise<IssuedMdoc> {
  const nameSpaces = new Map<string, Tag[]>();
  const valueDigests = new Map<string, Map<number, Buffer>>();
  let digestId = 0;

  for (const [ns, elements] of Object.entries(cred.namespaces)) {
    const items: Tag[] = [];
    const nsDigests = new Map<number, Buffer>();
    for (const [elementIdentifier, elementValue] of Object.entries(elements)) {
      const id = digestId++;
      const item = new Map<string, unknown>([
        ["digestID", id],
        ["random", randomBytes(16)],
        ["elementIdentifier", elementIdentifier],
        ["elementValue", elementValue],
      ]);
      const itemBytes = enc(item);
      items.push(tag24(itemBytes));
      nsDigests.set(id, sha256(itemBytes)); // digest over the tag-24 *content* bytes
    }
    nameSpaces.set(ns, items);
    valueDigests.set(ns, nsDigests);
  }

  const now = Math.floor(Date.now() / 1000);
  const mso = new Map<string, unknown>([
    ["version", "1.0"],
    ["digestAlgorithm", "SHA-256"],
    ["valueDigests", valueDigests],
    ["deviceKeyInfo", new Map([["deviceKey", jwkToCoseKey(holderPublicJwk)]])],
    ["docType", cred.docType],
    ["validityInfo", new Map<string, number>([
      ["signed", now],
      ["validFrom", now],
      ["validUntil", now + (cred.validityDays ?? 365) * 86400],
    ])],
  ]);

  // IETF Token Status List reference inside the MSO (mirrors SD-JWT VC `status`).
  if (cred.status) {
    mso.set("status", new Map([["status_list", new Map<string, unknown>([
      ["idx", cred.status.idx],
      ["uri", cred.status.uri],
    ])]]));
  }

  const issuerAuth = await coseSign1(issuerPrivateJwk, enc(tag24(enc(mso))));
  const issuerSigned = new Map<string, unknown>([
    ["nameSpaces", nameSpaces],
    ["issuerAuth", issuerAuth],
  ]);

  return { docType: cred.docType, issuerSigned: enc(issuerSigned).toString("base64url") };
}

// --- Presentation (holder) ------------------------------------------------------------------
/**
 * Build a DeviceResponse revealing only `reveal` ({ ns: [elementId,...] }), with a
 * deviceAuth COSE_Sign1 by the holder bound to the verifier `nonce`.
 */
export async function createMdocPresentation(
  issued: IssuedMdoc,
  holder: JWK | JwsSigner,
  reveal: Record<string, string[]>,
  audience: string,
  nonce: string,
): Promise<string> {
  const signer = asSigner(holder);
  const issuerSigned = dec(Buffer.from(issued.issuerSigned, "base64url")) as Map<string, unknown>;
  const allNs = issuerSigned.get("nameSpaces") as Map<string, Tag[]>;

  // Keep only requested items per namespace.
  const filtered = new Map<string, Tag[]>();
  for (const [ns, items] of allNs) {
    const wanted = new Set(reveal[ns] ?? []);
    const kept = items.filter((it) => {
      const item = dec(it.value as Buffer) as Map<string, unknown>;
      return wanted.has(item.get("elementIdentifier") as string);
    });
    if (kept.length) filtered.set(ns, kept);
  }

  const presentedIssuerSigned = new Map<string, unknown>([
    ["nameSpaces", filtered],
    ["issuerAuth", issuerSigned.get("issuerAuth")],
  ]);

  // DeviceAuthentication = [ "DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes ]
  // SessionTranscript is simplified here to bind audience + nonce.
  const sessionTranscript = new Map<string, string>([["aud", audience], ["nonce", nonce]]);
  const deviceAuthBytes = enc(["DeviceAuthentication", sessionTranscript, issued.docType, tag24(enc(new Map()))]);
  const deviceAuth = await coseSign1Raw((d) => signer.signRaw(d), deviceAuthBytes);

  const document = new Map<string, unknown>([
    ["docType", issued.docType],
    ["issuerSigned", presentedIssuerSigned],
    ["deviceSigned", new Map<string, unknown>([
      ["nameSpaces", tag24(enc(new Map()))],
      ["deviceAuth", new Map([["deviceSignature", deviceAuth]])],
    ])],
  ]);

  const deviceResponse = new Map<string, unknown>([
    ["version", "1.0"],
    ["documents", [document]],
    ["status", 0],
  ]);
  return enc(deviceResponse).toString("base64url");
}

// --- Verification (verifier) ----------------------------------------------------------------
export interface MdocVerificationResult {
  valid: boolean;
  docType?: string;
  disclosedClaims: Record<string, Record<string, unknown>>; // ns -> {element: value}
  /** Token Status List reference from the MSO, if present (for revocation checking). */
  status?: { idx: number; uri: string };
  errors: string[];
}

export async function verifyMdocPresentation(
  deviceResponseB64: string,
  issuerPublicJwk: JWK,
  expectedAudience: string,
  expectedNonce: string,
): Promise<MdocVerificationResult> {
  const errors: string[] = [];
  const disclosedClaims: Record<string, Record<string, unknown>> = {};
  let docType: string | undefined;
  let status: { idx: number; uri: string } | undefined;

  // Size check before try/catch: must throw, not silently fail, to prevent memory exhaustion.
  const rawBytes = Buffer.from(deviceResponseB64, "base64url");
  if (rawBytes.byteLength > MAX_CBOR_BYTES) {
    throw new Oid4vcError("invalid_presentation", `CBOR too large: ${rawBytes.byteLength} bytes`);
  }

  try {
    const resp = dec(rawBytes) as Map<string, unknown>;
    const doc = (resp.get("documents") as unknown[])[0] as Map<string, unknown>;
    docType = doc.get("docType") as string;
    const issuerSigned = doc.get("issuerSigned") as Map<string, unknown>;

    // 1. Verify issuerAuth and recover the MSO.
    const issuerAuth = issuerSigned.get("issuerAuth") as unknown[];
    const msoPayload = await coseSign1Verify(issuerPublicJwk, issuerAuth);
    const msoTag = safeDec(msoPayload) as Tag; // tag-24 wrapping MSO bytes
    const mso = safeDec(msoTag.value as Buffer) as Map<string, unknown>;

    // ISO 18013-5 §9.1.2.4: docType in MSO MUST match the docType in the surrounding Document.
    if (mso.get("docType") !== docType) {
      errors.push("docType mismatch between Document and MSO");
    }

    const valueDigests = mso.get("valueDigests") as Map<string, Map<number, Buffer>>;

    // 2. For each disclosed item, recompute its digest and confirm it matches the MSO.
    const nameSpaces = issuerSigned.get("nameSpaces") as Map<string, Tag[]>;
    for (const [ns, items] of nameSpaces) {
      const nsDigests = valueDigests.get(ns);
      disclosedClaims[ns] = {};
      for (const it of items) {
        const itemBytes = it.value as Buffer;
        const item = dec(itemBytes) as Map<string, unknown>;
        const id = item.get("digestID") as number;
        const expected = nsDigests?.get(id);
        if (!expected || !sha256(Buffer.from(itemBytes)).equals(Buffer.from(expected))) {
          errors.push(`digest mismatch for ${ns}/${String(item.get("elementIdentifier"))}`);
          continue;
        }
        disclosedClaims[ns][item.get("elementIdentifier") as string] = item.get("elementValue");
      }
    }

    // 3. Holder binding: verify deviceAuth against deviceKey in the MSO, bound to nonce/aud.
    const deviceKey = coseKeyToJwk((mso.get("deviceKeyInfo") as Map<string, unknown>).get("deviceKey") as Map<number, unknown>);
    const deviceSigned = doc.get("deviceSigned") as Map<string, unknown>;
    const deviceAuth = (deviceSigned.get("deviceAuth") as Map<string, unknown>).get("deviceSignature") as unknown[];
    const signedBytes = await coseSign1Verify(deviceKey, deviceAuth);
    const da = dec(signedBytes) as unknown[];
    const transcript = da[1] as Map<string, string>;
    if (transcript.get("aud") !== expectedAudience) errors.push("deviceAuth audience mismatch");
    if (transcript.get("nonce") !== expectedNonce) errors.push("deviceAuth nonce mismatch (replay)");

    // 4. Validity window (ISO 18013-5 §9.1.2.4).
    const validity = mso.get("validityInfo") as Map<string, number>;
    const now = Math.floor(Date.now() / 1000);
    if (validity.get("validUntil")! < now) errors.push("mdoc expired");
    const validFrom = validity.get("validFrom");
    if (typeof validFrom === "number" && validFrom > now) {
      errors.push("mdoc not yet valid (validFrom in the future)");
    }

    // 5. Expose the MSO status reference (revocation is checked by the caller).
    const statusMap = mso.get("status") as Map<string, unknown> | undefined;
    if (statusMap) {
      const sl = statusMap.get("status_list") as Map<string, unknown> | undefined;
      if (sl) status = { idx: sl.get("idx") as number, uri: sl.get("uri") as string };
    }
  } catch (e) {
    errors.push(`mdoc verification failed: ${(e as Error).message}`);
  }

  return { valid: errors.length === 0, docType, disclosedClaims, status, errors };
}
