/**
 * Headless end-to-end demo of the full issue -> hold -> present -> verify flow,
 * using only @digilompakko/core (no servers needed). Run: `npm run demo`.
 */
import {
  generateP256KeyPair,
  issueSdJwtVc,
  createPresentation,
  verifyPresentation,
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
const nonce = "nonce-" + Math.random().toString(36).slice(2);
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

process.exit(result.valid && !("family_name" in result.disclosedClaims) ? 0 : 1);
