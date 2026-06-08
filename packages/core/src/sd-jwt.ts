/**
 * Minimal but spec-faithful SD-JWT VC implementation.
 *
 * Format: IETF draft-ietf-oauth-sd-jwt-vc + draft-ietf-oauth-selective-disclosure-jwt.
 * Compact serialization:
 *   issued:        <JWS>~<Disclosure>~...~              (trailing tilde, no KB-JWT)
 *   presentation:  <JWS>~<Disclosure>~...~<KB-JWT>      (KB-JWT last, no trailing tilde)
 *
 * A Disclosure is base64url(JSON([salt, claimName, claimValue])).
 * The JWS payload carries `_sd`: an array of base64url(SHA-256(Disclosure)).
 * Holder binding uses the `cnf` claim (holder public JWK) + a Key Binding JWT.
 */
import { SignJWT, jwtVerify, importJWK, decodeJwt, decodeProtectedHeader, type JWK } from "jose";
import { ALG, SD_JWT_VC_TYP, type CredentialClaims, type IssuedCredential, type VerificationResult } from "./types.js";
import { b64url, sha256b64url, newSalt } from "./crypto.js";
import { asSigner, type JwsSigner } from "./keystore.js";

const SD_ALG = "sha-256";

interface Disclosure {
  encoded: string;
  digest: string;
  claimName: string;
  claimValue: unknown;
}

function makeDisclosure(claimName: string, claimValue: unknown): Disclosure {
  const encoded = b64url(JSON.stringify([newSalt(), claimName, claimValue]));
  return { encoded, digest: sha256b64url(encoded), claimName, claimValue };
}

/**
 * Issue an SD-JWT VC.
 * @param issuerPrivateJwk  Issuer signing key (ES256/P-256).
 * @param issuer            Issuer identifier (becomes `iss`).
 * @param holderPublicJwk   Holder key for holder binding (becomes `cnf.jwk`).
 */
export async function issueSdJwtVc(
  issuerPrivateJwk: JWK,
  issuer: string,
  holderPublicJwk: JWK,
  cred: CredentialClaims,
): Promise<IssuedCredential> {
  const disclosures = Object.entries(cred.claims).map(([k, v]) => makeDisclosure(k, v));

  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    vct: cred.vct,
    iss: issuer,
    iat: now,
    _sd_alg: SD_ALG,
    _sd: disclosures.map((d) => d.digest).sort(),
    cnf: { jwk: holderPublicJwk },
    ...cred.alwaysDisclosed,
  };
  if (cred.expiresInSeconds) payload.exp = now + cred.expiresInSeconds;

  const key = await importJWK(issuerPrivateJwk, ALG);
  const jws = await new SignJWT(payload)
    .setProtectedHeader({ alg: ALG, typ: SD_JWT_VC_TYP })
    .sign(key);

  const sdJwt = [jws, ...disclosures.map((d) => d.encoded)].join("~") + "~";
  return { sdJwt, vct: cred.vct };
}

/** Split a compact SD-JWT into its JWS, disclosures, and optional KB-JWT. */
export function parseCompact(compact: string): { jws: string; disclosures: string[]; kbJwt?: string } {
  const parts = compact.split("~");
  const jws = parts.shift() as string;
  let kbJwt: string | undefined;
  // Trailing empty string => issued form (no KB-JWT). Otherwise last part is the KB-JWT.
  if (parts.length && parts[parts.length - 1] === "") {
    parts.pop();
  } else if (parts.length) {
    kbJwt = parts.pop();
  }
  return { jws, disclosures: parts, kbJwt };
}

function decodeDisclosure(encoded: string): { salt: string; name: string; value: unknown } {
  const [salt, name, value] = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  return { salt, name, value };
}

/**
 * Holder side: produce a presentation that discloses only `claimsToReveal`,
 * then append a Key Binding JWT signed over the verifier's nonce + audience.
 */
export async function createPresentation(
  issuedSdJwt: string,
  holder: JWK | JwsSigner,
  claimsToReveal: string[],
  audience: string,
  nonce: string,
): Promise<string> {
  const signer = asSigner(holder);
  const { jws, disclosures } = parseCompact(issuedSdJwt);
  const kept = disclosures.filter((d) => claimsToReveal.includes(decodeDisclosure(d).name));

  // The string the KB-JWT commits to: everything up to and including the final tilde.
  const presentationHead = [jws, ...kept].join("~") + "~";
  const sdHash = sha256b64url(presentationHead);

  // Signed inside the keystore (WSCD boundary) — the private key is never handled here.
  const kbJwt = await signer.signJwt(
    { alg: ALG, typ: "kb+jwt" },
    { iat: Math.floor(Date.now() / 1000), nonce, aud: audience, sd_hash: sdHash },
  );

  return presentationHead + kbJwt;
}

/**
 * Verifier side: validate issuer signature, disclosure digests, holder binding,
 * replay nonce and audience. Returns only the disclosed claims.
 */
export async function verifyPresentation(
  presentation: string,
  issuerPublicJwk: JWK,
  expectedAudience: string,
  expectedNonce: string,
): Promise<VerificationResult> {
  const errors: string[] = [];
  const disclosedClaims: Record<string, unknown> = {};
  const issuerClaims: Record<string, unknown> = {};
  let issuer: string | undefined;
  let vct: string | undefined;

  try {
    const { jws, disclosures, kbJwt } = parseCompact(presentation);

    // 1. Verify the issuer's signature over the SD-JWT.
    const issuerKey = await importJWK(issuerPublicJwk, ALG);
    const { payload } = await jwtVerify(jws, issuerKey, { typ: SD_JWT_VC_TYP });
    issuer = payload.iss as string;
    vct = payload.vct as string;

    // Expose always-visible issuer claims (excluding SD-JWT internals) to the caller.
    for (const [k, v] of Object.entries(payload)) {
      if (k !== "_sd" && k !== "_sd_alg" && k !== "cnf") issuerClaims[k] = v;
    }

    // 2. Recompute each disclosure digest and confirm it is in `_sd`.
    const sdSet = new Set((payload._sd as string[]) ?? []);
    for (const d of disclosures) {
      const digest = sha256b64url(d);
      if (!sdSet.has(digest)) {
        errors.push(`Disclosure not present in _sd digest set: ${decodeDisclosure(d).name}`);
        continue;
      }
      const { name, value } = decodeDisclosure(d);
      disclosedClaims[name] = value;
    }

    // 3. Holder binding: a KB-JWT must be present and signed by the cnf key.
    const cnf = payload.cnf as { jwk?: JWK } | undefined;
    if (!kbJwt) {
      errors.push("Missing Key Binding JWT (holder binding required).");
    } else if (!cnf?.jwk) {
      errors.push("Credential has no cnf.jwk; cannot verify holder binding.");
    } else {
      const holderKey = await importJWK(cnf.jwk, ALG);
      const { payload: kb } = await jwtVerify(kbJwt, holderKey, { typ: "kb+jwt" });

      if (kb.aud !== expectedAudience) errors.push(`KB-JWT audience mismatch: ${kb.aud}`);
      if (kb.nonce !== expectedNonce) errors.push("KB-JWT nonce mismatch (possible replay).");

      // sd_hash must commit to exactly the presented SD-JWT (excluding the KB-JWT).
      const head = presentation.slice(0, presentation.lastIndexOf("~") + 1);
      if (kb.sd_hash !== sha256b64url(head)) errors.push("KB-JWT sd_hash mismatch (tampering).");
    }

    // 4. Expiry.
    if (payload.exp && (payload.exp as number) < Math.floor(Date.now() / 1000)) {
      errors.push("Credential expired.");
    }
  } catch (e) {
    errors.push(`Verification failed: ${(e as Error).message}`);
  }

  return { valid: errors.length === 0, disclosedClaims, issuerClaims, errors, issuer, vct };
}

/** Convenience: read the issued credential's payload without verifying (UI display). */
export function peekPayload(compact: string): Record<string, unknown> {
  const { jws } = parseCompact(compact);
  return decodeJwt(jws) as Record<string, unknown>;
}

/** Convenience: read the protected header (e.g. to find typ). */
export function peekHeader(compact: string): Record<string, unknown> {
  const { jws } = parseCompact(compact);
  return decodeProtectedHeader(jws) as Record<string, unknown>;
}
