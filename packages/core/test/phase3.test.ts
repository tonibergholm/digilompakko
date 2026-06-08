import { test } from "node:test";
import assert from "node:assert/strict";
import { jwtVerify, importJWK } from "jose";
import {
  SoftwareKeyStore,
  pkceS256Challenge,
  verifyPkce,
  RelyingPartyRegistry,
  issueSdJwtVc,
  createPresentation,
  verifyPresentation,
  generateP256KeyPair,
} from "../src/index.js";

test("SoftwareKeyStore: signs a verifiable JWT and never exposes the private key", async () => {
  const ks = new SoftwareKeyStore();
  const { keyId, publicJwk } = await ks.generateKey();
  const signer = ks.getSigner(keyId);

  const jwt = await signer.signJwt({ alg: "ES256", typ: "JWT" }, { hello: "world" });
  const key = await importJWK(publicJwk, "ES256");
  const { payload } = await jwtVerify(jwt, key);
  assert.equal(payload.hello, "world");

  // The signer interface exposes only the public key — no private material.
  assert.equal((signer as Record<string, unknown>).privateJwk, undefined);
  assert.equal(publicJwk.d, undefined);
});

test("keystore signer works end-to-end as an SD-JWT VC holder (WSCD boundary)", async () => {
  const issuer = await generateP256KeyPair();
  const ks = new SoftwareKeyStore();
  const { keyId, publicJwk } = await ks.generateKey();

  const issued = await issueSdJwtVc(issuer.privateJwk, "https://issuer.example", publicJwk, {
    vct: "eu.europa.ec.eudi.pid.1",
    claims: { given_name: "Toni", age_over_18: true },
  });

  // Holder signs the presentation through the keystore signer, not a raw key.
  const pres = await createPresentation(issued.sdJwt, ks.getSigner(keyId), ["age_over_18"], "https://verifier.example", "n1");
  const result = await verifyPresentation(pres, issuer.publicJwk, "https://verifier.example", "n1");
  assert.equal(result.valid, true, JSON.stringify(result.errors));
  assert.equal(result.disclosedClaims.age_over_18, true);
});

test("PKCE S256: matching verifier passes, wrong verifier fails", () => {
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = pkceS256Challenge(verifier);
  assert.doesNotThrow(() => verifyPkce(verifier, challenge));
  assert.throws(() => verifyPkce("wrong-verifier", challenge), /PKCE verification failed/);
  assert.throws(() => verifyPkce(verifier, challenge, "plain"), /unsupported PKCE method/);
});

test("RelyingPartyRegistry: registration + attribute entitlement gate", () => {
  const reg = new RelyingPartyRegistry();
  reg.register({ client_id: "rp-1", name: "Demo RP", entitled_attributes: ["given_name", "age_over_18"] });

  assert.equal(reg.isRegistered("rp-1"), true);
  assert.equal(reg.isRegistered("rp-x"), false);
  assert.throws(() => reg.assertRegistered("rp-x"), /not registered/);

  assert.doesNotThrow(() => reg.assertEntitled("rp-1", ["given_name"]));
  assert.throws(() => reg.assertEntitled("rp-1", ["given_name", "ssn"]), /not entitled to: ssn/);
});
