import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateP256KeyPair,
  issueMdoc,
  createMdocPresentation,
  verifyMdocPresentation,
  StatusList,
  buildStatusListToken,
  readStatus,
  STATUS_INVALID,
  signRequestObject,
  verifyRequestObject,
} from "../src/index.js";

const NS = "org.iso.18013.5.1";
const AUD = "https://verifier.example";
const STATUS_URI = "https://issuer.example/statuslist";

test("mdoc revocation: MSO status reference is surfaced and reflects the status list", async () => {
  const issuer = await generateP256KeyPair();
  const holder = await generateP256KeyPair();
  const list = new StatusList(64);
  const idx = 7;

  const mdl = await issueMdoc(issuer.privateJwk, holder.publicJwk, {
    docType: "org.iso.18013.5.1.mDL",
    namespaces: { [NS]: { given_name: "Toni", age_over_18: true } },
    status: { idx, uri: STATUS_URI },
  });
  const dr = await createMdocPresentation(mdl, holder.privateJwk, { [NS]: ["age_over_18"] }, AUD, "n1");
  const r = await verifyMdocPresentation(dr, issuer.publicJwk, AUD, "n1");

  assert.equal(r.valid, true, JSON.stringify(r.errors));
  assert.deepEqual(r.status, { idx, uri: STATUS_URI }); // reference surfaced

  // Valid while the bit is 0; revoked once set.
  let token = await buildStatusListToken(issuer.privateJwk, "https://issuer.example", STATUS_URI, list);
  assert.notEqual(await readStatus(token, idx, issuer.publicJwk), STATUS_INVALID);
  list.set(idx, 1);
  token = await buildStatusListToken(issuer.privateJwk, "https://issuer.example", STATUS_URI, list);
  assert.equal(await readStatus(token, idx, issuer.publicJwk), STATUS_INVALID);
});

test("signed request object (JAR): valid passes, tampered/forged fails", async () => {
  const rp = await generateP256KeyPair();
  const claims = { client_id: "https://verifier.example", nonce: "abc", response_uri: "https://verifier.example/r" };

  const jwt = await signRequestObject(rp.privateJwk, claims);
  const verified = await verifyRequestObject(jwt, rp.publicJwk);
  assert.equal(verified.client_id, "https://verifier.example");
  assert.equal(verified.nonce, "abc");

  // Wrong key (impersonating the RP) must fail.
  const attacker = await generateP256KeyPair();
  await assert.rejects(() => verifyRequestObject(jwt, attacker.publicJwk), /signature invalid/);

  // Tampered payload must fail.
  const parts = jwt.split(".");
  const forgedPayload = Buffer.from(JSON.stringify({ ...claims, nonce: "evil" })).toString("base64url");
  await assert.rejects(() => verifyRequestObject(`${parts[0]}.${forgedPayload}.${parts[2]}`, rp.publicJwk), /signature invalid/);
});
