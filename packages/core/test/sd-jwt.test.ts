import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateP256KeyPair,
  issueSdJwtVc,
  createPresentation,
  verifyPresentation,
} from "../src/index.js";

const ISSUER = "https://issuer.example";
const AUD = "https://verifier.example";

async function setup() {
  const issuerKeys = await generateP256KeyPair();
  const holderKeys = await generateP256KeyPair();
  const issued = await issueSdJwtVc(issuerKeys.privateJwk, ISSUER, holderKeys.publicJwk, {
    vct: "eu.europa.ec.eudi.pid.1",
    claims: {
      given_name: "Toni",
      family_name: "Bergholm",
      birthdate: "1985-04-12",
      age_over_18: true,
    },
    expiresInSeconds: 3600,
  });
  return { issuerKeys, holderKeys, issued };
}

test("selective disclosure: verifier sees only revealed claims", async () => {
  const { issuerKeys, holderKeys, issued } = await setup();
  const nonce = "n-" + Math.random().toString(36).slice(2);

  const presentation = await createPresentation(
    issued.sdJwt,
    holderKeys.privateJwk,
    ["given_name", "age_over_18"], // reveal only these
    AUD,
    nonce,
  );

  const result = await verifyPresentation(presentation, issuerKeys.publicJwk, AUD, nonce);
  assert.equal(result.valid, true, JSON.stringify(result.errors));
  assert.deepEqual(Object.keys(result.disclosedClaims).sort(), ["age_over_18", "given_name"]);
  assert.equal(result.disclosedClaims.family_name, undefined); // NOT disclosed
  assert.equal(result.disclosedClaims.given_name, "Toni");
  assert.equal(result.issuer, ISSUER);
});

test("replay protection: wrong nonce fails", async () => {
  const { issuerKeys, holderKeys, issued } = await setup();
  const presentation = await createPresentation(
    issued.sdJwt, holderKeys.privateJwk, ["given_name"], AUD, "good-nonce",
  );
  const result = await verifyPresentation(presentation, issuerKeys.publicJwk, AUD, "ATTACKER-NONCE");
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("nonce")));
});

test("holder binding: presentation signed by a different holder key fails", async () => {
  const { issuerKeys, issued } = await setup();
  const attacker = await generateP256KeyPair();
  const presentation = await createPresentation(
    issued.sdJwt, attacker.privateJwk, ["given_name"], AUD, "n",
  );
  const result = await verifyPresentation(presentation, issuerKeys.publicJwk, AUD, "n");
  assert.equal(result.valid, false);
});

test("tamper: forged issuer signature fails", async () => {
  const { holderKeys, issued } = await setup();
  const wrongIssuer = await generateP256KeyPair();
  const presentation = await createPresentation(
    issued.sdJwt, holderKeys.privateJwk, ["given_name"], AUD, "n",
  );
  const result = await verifyPresentation(presentation, wrongIssuer.publicJwk, AUD, "n");
  assert.equal(result.valid, false);
});
