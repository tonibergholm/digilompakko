import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateP256KeyPair,
  issueMdoc,
  createMdocPresentation,
  verifyMdocPresentation,
  MAX_CBOR_BYTES,
} from "../src/index.js";

const DOCTYPE = "org.iso.18013.5.1.mDL";
const NS = "org.iso.18013.5.1";
const AUD = "https://verifier.example";

async function setup() {
  const issuer = await generateP256KeyPair();
  const holder = await generateP256KeyPair();
  const issued = await issueMdoc(issuer.privateJwk, holder.publicJwk, {
    docType: DOCTYPE,
    namespaces: {
      [NS]: { family_name: "Bergholm", given_name: "Toni", age_over_18: true, document_number: "X1234567" },
    },
  });
  const nonce = "n-" + Math.random().toString(36).slice(2);
  const presentation = await createMdocPresentation(issued, holder.privateJwk, { [NS]: ["given_name"] }, AUD, nonce);
  return { issuer, holder, issued, nonce, presentation, issuerPublicJwk: issuer.publicJwk };
}

test("mdoc: selective disclosure reveals only requested elements", async () => {
  const { issuer, holder, issued } = await setup();
  const nonce = "n-" + Math.random().toString(36).slice(2);
  const dr = await createMdocPresentation(issued, holder.privateJwk, { [NS]: ["given_name", "age_over_18"] }, AUD, nonce);

  const r = await verifyMdocPresentation(dr, issuer.publicJwk, AUD, nonce);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
  assert.deepEqual(Object.keys(r.disclosedClaims[NS]).sort(), ["age_over_18", "given_name"]);
  assert.equal(r.disclosedClaims[NS].family_name, undefined); // withheld
  assert.equal(r.disclosedClaims[NS].given_name, "Toni");
  assert.equal(r.docType, DOCTYPE);
});

test("mdoc: wrong nonce fails (replay protection)", async () => {
  const { issuer, holder, issued } = await setup();
  const dr = await createMdocPresentation(issued, holder.privateJwk, { [NS]: ["given_name"] }, AUD, "good");
  const r = await verifyMdocPresentation(dr, issuer.publicJwk, AUD, "ATTACKER");
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("nonce")));
});

test("mdoc: forged issuer key rejected", async () => {
  const { holder, issued } = await setup();
  const wrong = await generateP256KeyPair();
  const dr = await createMdocPresentation(issued, holder.privateJwk, { [NS]: ["given_name"] }, AUD, "n");
  const r = await verifyMdocPresentation(dr, wrong.publicJwk, AUD, "n");
  assert.equal(r.valid, false);
});

test("mdoc: device binding — different holder key rejected", async () => {
  const { issuer, issued } = await setup();
  const attacker = await generateP256KeyPair();
  const dr = await createMdocPresentation(issued, attacker.privateJwk, { [NS]: ["given_name"] }, AUD, "n");
  const r = await verifyMdocPresentation(dr, issuer.publicJwk, AUD, "n");
  assert.equal(r.valid, false);
});

test("mdoc: CBOR larger than MAX_CBOR_BYTES is rejected before decode", async () => {
  const s = await setup();
  // one byte over the limit — too large to be a real DeviceResponse
  const huge = Buffer.alloc(MAX_CBOR_BYTES + 1).toString("base64url");
  await assert.rejects(
    () => verifyMdocPresentation(huge, s.issuerPublicJwk, AUD, s.nonce),
    /too large/i,
  );
});

test("mdoc: credential with validFrom in the future is rejected", async () => {
  const issuer = await generateP256KeyPair();
  const holder = await generateP256KeyPair();
  const futureValidFrom = Math.floor(Date.now() / 1000) + 86400; // valid from tomorrow
  const issued = await issueMdoc(issuer.privateJwk, holder.publicJwk, {
    docType: DOCTYPE,
    namespaces: { [NS]: { given_name: "Toni" } },
    _testValidFrom: futureValidFrom,
  });
  const nonce = "n1";
  const dr = await createMdocPresentation(issued, holder.privateJwk, { [NS]: ["given_name"] }, AUD, nonce);
  const r = await verifyMdocPresentation(dr, issuer.publicJwk, AUD, nonce);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("validFrom")), `expected validFrom error, got: ${JSON.stringify(r.errors)}`);
});
