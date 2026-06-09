/**
 * Adversarial tests for verifyPresentationRequest (HIGH-1 fix).
 *
 * The tests prove the negative: every path that must be rejected IS rejected,
 * and only a fully-valid JAR from a trusted RP passes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateP256KeyPair, signRequestObject, verifyPresentationRequest } from "../src/index.js";

const CLIENT_ID = "https://verifier.example";
const WALLET_AUD = "digilompakko-wallet";

async function makeJar(
  privateJwk: Awaited<ReturnType<typeof generateP256KeyPair>>["privateJwk"],
  overrides: Record<string, unknown> = {},
): Promise<string> {
  return signRequestObject(privateJwk, {
    client_id: CLIENT_ID,
    nonce: "n1",
    response_uri: `${CLIENT_ID}/response`,
    aud: WALLET_AUD,
    ...overrides,
  });
}

test("verifyPresentationRequest: valid JAR from trusted RP passes", async () => {
  const rp = await generateP256KeyPair();
  const jwt = await makeJar(rp.privateJwk);
  const trustedRps = new Map([[CLIENT_ID, rp.publicJwk]]);
  const payload = await verifyPresentationRequest(jwt, trustedRps, { expectedAudience: WALLET_AUD });
  assert.equal(payload.client_id, CLIENT_ID);
  assert.equal(payload.nonce, "n1");
});

test("verifyPresentationRequest: untrusted client_id is rejected (HIGH-1a)", async () => {
  const rp = await generateP256KeyPair();
  const jwt = await makeJar(rp.privateJwk);
  // Empty allowlist — client_id not trusted.
  const trustedRps = new Map<string, (typeof rp)["publicJwk"]>();
  await assert.rejects(
    () => verifyPresentationRequest(jwt, trustedRps, { expectedAudience: WALLET_AUD }),
    { code: "access_denied" },
  );
});

test("verifyPresentationRequest: attacker-substituted key is rejected", async () => {
  const rp = await generateP256KeyPair();
  const attacker = await generateP256KeyPair();
  const jwt = await makeJar(rp.privateJwk);
  // Allowlist maps client_id to the ATTACKER's key — signature check must still fail.
  const trustedRps = new Map([[CLIENT_ID, attacker.publicJwk]]);
  await assert.rejects(
    () => verifyPresentationRequest(jwt, trustedRps, { expectedAudience: WALLET_AUD }),
    /verification failed/,
  );
});

test("verifyPresentationRequest: wrong aud is rejected", async () => {
  const rp = await generateP256KeyPair();
  const jwt = await makeJar(rp.privateJwk);
  const trustedRps = new Map([[CLIENT_ID, rp.publicJwk]]);
  await assert.rejects(
    () => verifyPresentationRequest(jwt, trustedRps, { expectedAudience: "different-wallet" }),
    /verification failed/,
  );
});

test("verifyPresentationRequest: expired JAR is rejected", async () => {
  const rp = await generateP256KeyPair();
  const jwt = await makeJar(rp.privateJwk);
  const trustedRps = new Map([[CLIENT_ID, rp.publicJwk]]);
  // Advance clock 200 seconds past issuance (beyond the 120s window).
  const futureNow = Math.floor(Date.now() / 1000) + 200;
  await assert.rejects(
    () => verifyPresentationRequest(jwt, trustedRps, { expectedAudience: WALLET_AUD, now: futureNow }),
    /verification failed/,
  );
});

test("verifyPresentationRequest: tampered payload is rejected", async () => {
  const rp = await generateP256KeyPair();
  const jwt = await makeJar(rp.privateJwk);
  const trustedRps = new Map([[CLIENT_ID, rp.publicJwk]]);
  // Forge a new payload with an evil nonce — signature mismatch.
  const [header, , sig] = jwt.split(".");
  const forgedPayload = Buffer.from(JSON.stringify({ client_id: CLIENT_ID, nonce: "evil", aud: WALLET_AUD })).toString("base64url");
  const forged = `${header}.${forgedPayload}.${sig}`;
  await assert.rejects(
    () => verifyPresentationRequest(forged, trustedRps, { expectedAudience: WALLET_AUD }),
    /verification failed/,
  );
});

test("signRequestObject: emits exp (short-lived JAR)", async () => {
  const rp = await generateP256KeyPair();
  const jwt = await makeJar(rp.privateJwk);
  const [, rawPayload] = jwt.split(".");
  const payload = JSON.parse(Buffer.from(rawPayload, "base64url").toString()) as Record<string, unknown>;
  assert.ok(typeof payload.exp === "number", "exp must be present");
  assert.ok(typeof payload.iat === "number", "iat must be present");
  // exp should be ~120 seconds after iat.
  assert.ok((payload.exp as number) - (payload.iat as number) <= 120, "exp window must be ≤120s");
  assert.ok((payload.exp as number) - (payload.iat as number) >= 118, "exp window must be ≥118s");
});
