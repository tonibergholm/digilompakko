/**
 * Headless end-to-end demo of the full issue -> hold -> present -> verify flow,
 * using only @digilompakko/core (no servers needed). Run: `npm run demo`.
 */
import { randomUUID } from "node:crypto";
import {
  generateP256KeyPair,
  issueSdJwtVc,
  createPresentation,
  verifyPresentation,
  issueMdoc,
  createMdocPresentation,
  verifyMdocPresentation,
} from "@digilompakko/core";

const ISSUER = "https://issuer.demo";
const VERIFIER = "https://verifier.demo";

console.log("→ Generating issuer + holder keys (ES256 / P-256)…");
const issuer = await generateP256KeyPair();
const holder = await generateP256KeyPair();

console.log("→ Issuer issues a PID SD-JWT VC bound to the holder key…");
const issued = await issueSdJwtVc(issuer.privateJwk, ISSUER, holder.publicJwk, {
  vct: "eu.europa.ec.eudi.pid.1",
  claims: { given_name: "Toni", family_name: "Bergholm", birthdate: "1985-04-12", age_over_18: true },
  alwaysDisclosed: { issuing_country: "FI" },
  expiresInSeconds: 3600,
});
console.log(`  credential length: ${issued.sdJwt.length} chars\n`);

console.log("→ Verifier nonce + holder presents ONLY given_name + age_over_18…");
const nonce = randomUUID();
const presentation = await createPresentation(
  issued.sdJwt, holder.privateJwk, ["given_name", "age_over_18"], VERIFIER, nonce,
);

console.log("→ Verifier validates…\n");
const result = await verifyPresentation(presentation, issuer.publicJwk, VERIFIER, nonce);

console.log("Valid:           ", result.valid);
console.log("Issuer:          ", result.issuer);
console.log("Disclosed claims:", result.disclosedClaims);
console.log("family_name leaked?", "family_name" in result.disclosedClaims ? "YES (bug!)" : "no ✓");
if (result.errors.length) console.log("Errors:", result.errors);

// --- Second format: ISO 18013-5 mdoc / mDL --------------------------------------------------
console.log("\n=== ISO 18013-5 mdoc / mDL ===");
const NS = "org.iso.18013.5.1";
console.log("→ Issuer issues an mDL bound to the holder device key…");
const mdl = await issueMdoc(issuer.privateJwk, holder.publicJwk, {
  docType: "org.iso.18013.5.1.mDL",
  namespaces: { [NS]: { family_name: "Bergholm", given_name: "Toni", age_over_18: true, document_number: "X1234567" } },
});

const mNonce = randomUUID();
console.log("→ Holder presents ONLY age_over_18…");
const dr = await createMdocPresentation(mdl, holder.privateJwk, { [NS]: ["age_over_18"] }, VERIFIER, mNonce);
const mResult = await verifyMdocPresentation(dr, issuer.publicJwk, VERIFIER, mNonce);

console.log("Valid:           ", mResult.valid);
console.log("Disclosed:       ", mResult.disclosedClaims[NS]);
console.log("document_number leaked?", "document_number" in (mResult.disclosedClaims[NS] ?? {}) ? "YES (bug!)" : "no ✓");
if (mResult.errors.length) console.log("Errors:", mResult.errors);

const sdOk = result.valid && !("family_name" in result.disclosedClaims);
const mOk = mResult.valid && !("document_number" in (mResult.disclosedClaims[NS] ?? {}));
process.exit(sdOk && mOk ? 0 : 1);
