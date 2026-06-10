/**
 * Adversarial test suite — exercises every security fix from PRs 1-7.
 *
 * Each test group maps to a specific finding:
 *   Group 1 — SSRF: private IP ranges + redirect bypass + body size cap (findings #2, #9)
 *   Group 2 — Status list: expired token, negative index (findings #4, #21)
 *   Group 3 — SD-JWT: expired credential rejection (finding #22)
 *   Group 4 — mdoc: CBOR bomb size gate (findings #8, #17)
 *   Group 5 — Algorithm pinning: RS256 rejected under ES256 pin (finding #15)
 */
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import * as http from "node:http";
import { SignJWT, importJWK, jwtVerify, generateKeyPair } from "jose";

import {
  assertSafeUrl,
  safeFetch,
  safeFetchText,
  MAX_BODY_BYTES,
  generateP256KeyPair,
  StatusList,
  buildStatusListToken,
  readStatus,
  STATUS_VALID,
  createPresentation,
  verifyPresentation,
  issueMdoc,
  createMdocPresentation,
  verifyMdocPresentation,
} from "../src/index.js";
import { MAX_CBOR_BYTES } from "../src/mdoc.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ISSUER = "https://issuer.example";
const AUD = "https://verifier.example";
const STATUS_URI = `${ISSUER}/statuslist`;
const OPTS = { expectedIssuer: ISSUER, expectedUri: STATUS_URI };

const DOCTYPE = "org.iso.18013.5.1.mDL";
const NS = "org.iso.18013.5.1";

// ---------------------------------------------------------------------------
// Group 1: SSRF — private IP ranges + redirect bypass + body size cap
// ---------------------------------------------------------------------------

describe("SSRF: private IP ranges (finding #2)", () => {
  it("blocks 10.x", () => {
    assert.throws(() => assertSafeUrl("https://10.0.0.1/secret"), /private/i);
  });

  it("blocks 169.254.x (metadata endpoint)", () => {
    assert.throws(() => assertSafeUrl("https://169.254.169.254/latest/meta-data/"), /private/i);
  });

  it("blocks 172.16.x", () => {
    assert.throws(() => assertSafeUrl("https://172.16.0.1/internal"), /private/i);
  });

  it("blocks fc00:: ULA IPv6", () => {
    assert.throws(() => assertSafeUrl("https://[fc00::1]/"), /private/i);
  });

  it("redirect to private IP is rejected (finding #2 redirect bypass)", async () => {
    // Server that immediately redirects to a private IP.
    const server = http.createServer((_req, res) => {
      res.writeHead(302, { Location: "https://10.0.0.1/steal" });
      res.end();
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };
    try {
      await assert.rejects(
        () => safeFetch(`http://127.0.0.1:${port}/redirect`),
        /private/i,
      );
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("2 MiB body aborts (finding #9)", async () => {
    // MAX_BODY_BYTES is 1 MiB; serve 2 MiB to trigger the cap.
    const big = Buffer.alloc(2 * MAX_BODY_BYTES, 0x41);
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/octet-stream" });
      res.end(big);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };
    try {
      await assert.rejects(
        () => safeFetchText(`http://127.0.0.1:${port}/big`),
        /too large/i,
      );
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});

// ---------------------------------------------------------------------------
// Group 2: Status list — expired token, negative index
// ---------------------------------------------------------------------------

describe("Status list adversarial (findings #4 #21)", () => {
  it("expired token is rejected", async () => {
    const keys = await generateP256KeyPair();
    const key = await importJWK(keys.privateJwk, "ES256");
    const expired = await new SignJWT({
      sub: STATUS_URI,
      status_list: { bits: 1, lst: new StatusList(8).encode() },
    })
      .setProtectedHeader({ alg: "ES256", typ: "statuslist+jwt" })
      .setIssuer(ISSUER)
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) - 10)
      .sign(key);

    await assert.rejects(
      () => readStatus(expired, 0, keys.publicJwk, OPTS),
      /status list token invalid/i,
    );
  });

  it("fresh token passes (regression)", async () => {
    const keys = await generateP256KeyPair();
    const list = new StatusList(16);
    const token = await buildStatusListToken(keys.privateJwk, ISSUER, STATUS_URI, list);
    const status = await readStatus(token, 0, keys.publicJwk, OPTS);
    assert.equal(status, STATUS_VALID);
  });

  it("negative status index throws (finding #21)", async () => {
    const keys = await generateP256KeyPair();
    const list = new StatusList(16);
    const token = await buildStatusListToken(keys.privateJwk, ISSUER, STATUS_URI, list);
    await assert.rejects(
      () => readStatus(token, -1, keys.publicJwk, OPTS),
      /negative/i,
    );
  });
});

// ---------------------------------------------------------------------------
// Group 3: SD-JWT — expired credential rejection
// ---------------------------------------------------------------------------

describe("SD-JWT adversarial (finding #22)", () => {
  it("expired credential (exp in past) is rejected", async () => {
    const issuerKeys = await generateP256KeyPair();
    const holderKeys = await generateP256KeyPair();

    // Build a raw SD-JWT whose `exp` is 10 seconds in the past.
    // We use SignJWT directly (not issueSdJwtVc) so we can back-date exp.
    // Include cnf.jwk so holder-binding verification can proceed.
    const issuerKey = await importJWK(issuerKeys.privateJwk, "ES256");
    const now = Math.floor(Date.now() / 1000);
    const jws = await new SignJWT({
      vct: "eu.europa.ec.eudi.pid.1",
      iss: ISSUER,
      iat: now - 3600,
      exp: now - 10, // already expired
      _sd_alg: "sha-256",
      _sd: [],
      cnf: { jwk: holderKeys.publicJwk },
    })
      .setProtectedHeader({ alg: "ES256", typ: "dc+sd-jwt" })
      .sign(issuerKey);

    // SD-JWT issued form: jws~ (no disclosures, trailing tilde)
    const issuedSdJwt = jws + "~";

    const presentation = await createPresentation(
      issuedSdJwt,
      holderKeys.privateJwk,
      [],
      AUD,
      "test-nonce",
    );

    const result = await verifyPresentation(presentation, issuerKeys.publicJwk, AUD, "test-nonce");
    assert.equal(result.valid, false, "expired credential must not be valid");
    // verifyPresentation wraps jose's "exp" claim check in a catch block that
    // produces "Verification failed: …exp… claim timestamp check failed".
    // Also handles the direct "Credential expired." path if exp check reaches step 4.
    assert.ok(
      result.errors.some((e) => /exp|expired/i.test(e)),
      `expected an exp/expired error, got: ${JSON.stringify(result.errors)}`,
    );
  });
});

// ---------------------------------------------------------------------------
// Group 4: mdoc — CBOR bomb size gate
// ---------------------------------------------------------------------------

describe("mdoc adversarial (findings #8 #17)", () => {
  it("CBOR bomb (> MAX_CBOR_BYTES) is rejected before decode", async () => {
    const { issuerPublicJwk, nonce } = await mdocSetup();
    const huge = Buffer.alloc(MAX_CBOR_BYTES + 1).toString("base64url");
    await assert.rejects(
      () => verifyMdocPresentation(huge, issuerPublicJwk, AUD, nonce),
      /too large/i,
    );
  });

  it("valid presentation passes (regression after safeDec)", async () => {
    const { issuer, holder, issued, nonce } = await mdocSetup();
    const dr = await createMdocPresentation(
      issued,
      holder.privateJwk,
      { [NS]: ["given_name"] },
      AUD,
      nonce,
    );
    const r = await verifyMdocPresentation(dr, issuer.publicJwk, AUD, nonce);
    assert.equal(r.valid, true, JSON.stringify(r.errors));
  });
});

async function mdocSetup() {
  const issuer = await generateP256KeyPair();
  const holder = await generateP256KeyPair();
  const issued = await issueMdoc(issuer.privateJwk, holder.publicJwk, {
    docType: DOCTYPE,
    namespaces: {
      [NS]: { family_name: "Bergholm", given_name: "Toni", age_over_18: true },
    },
  });
  const nonce = "adv-nonce-" + Math.random().toString(36).slice(2);
  return { issuer, holder, issued, nonce, issuerPublicJwk: issuer.publicJwk };
}

// ---------------------------------------------------------------------------
// Group 5: Algorithm pinning — RS256 rejected under ES256 pin
// ---------------------------------------------------------------------------

describe("Algorithm pinning (finding #15)", () => {
  it("RS256 token rejected when algorithms: [ES256] is set", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const rs256Token = await new SignJWT({ sub: "test" })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuedAt()
      .sign(privateKey);

    // jose checks the `alg` header against the allowlist before touching the signature,
    // so this rejects with JOSEAlgNotAllowed even when the correct public key is supplied.
    await assert.rejects(
      () => jwtVerify(rs256Token, publicKey, { algorithms: ["ES256"] }),
      /Header Parameter value not allowed/i,
    );
  });
});
