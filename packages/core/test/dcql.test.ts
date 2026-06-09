/**
 * Tests for checkDcqlSatisfied (HIGH-3 fix).
 *
 * Proves the negative: a presentation that omits required claims MUST be detected as
 * not satisfying the DCQL query, and `false`/`0`/`""` are valid disclosed values.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkDcqlSatisfied } from "../src/index.js";

const SD_JWT_CLAIMS = [
  { path: ["given_name"] },
  { path: ["family_name"] },
  { path: ["age_over_18"] },
];

const MDOC_CLAIMS = [
  { path: ["org.iso.18013.5.1", "given_name"] },
  { path: ["org.iso.18013.5.1", "family_name"] },
  { path: ["org.iso.18013.5.1", "age_over_18"] },
];

test("checkDcqlSatisfied: all claims present → no missing paths", () => {
  const disclosed = { given_name: "Toni", family_name: "Bergholm", age_over_18: true };
  assert.deepEqual(checkDcqlSatisfied(SD_JWT_CLAIMS, disclosed), []);
});

test("checkDcqlSatisfied: zero disclosures → all paths missing (HIGH-3 proof)", () => {
  const missing = checkDcqlSatisfied(SD_JWT_CLAIMS, {});
  assert.deepEqual(missing, ["given_name", "family_name", "age_over_18"]);
});

test("checkDcqlSatisfied: one claim omitted → that path returned", () => {
  const disclosed = { given_name: "Toni", family_name: "Bergholm" }; // no age_over_18
  const missing = checkDcqlSatisfied(SD_JWT_CLAIMS, disclosed);
  assert.deepEqual(missing, ["age_over_18"]);
});

test("checkDcqlSatisfied: false and 0 are valid disclosed values (not treated as missing)", () => {
  const disclosed = { given_name: "Toni", family_name: "Bergholm", age_over_18: false };
  assert.deepEqual(checkDcqlSatisfied(SD_JWT_CLAIMS, disclosed), []);

  const disclosed2 = { score: 0, label: "", flag: false };
  assert.deepEqual(
    checkDcqlSatisfied([{ path: ["score"] }, { path: ["label"] }, { path: ["flag"] }], disclosed2),
    [],
  );
});

test("checkDcqlSatisfied: null claim value is treated as missing", () => {
  const disclosed: Record<string, unknown> = { given_name: "Toni", family_name: null, age_over_18: true };
  const missing = checkDcqlSatisfied(SD_JWT_CLAIMS, disclosed);
  assert.deepEqual(missing, ["family_name"]);
});

test("checkDcqlSatisfied: mdoc namespace+element paths — all present", () => {
  const disclosed = { "org.iso.18013.5.1": { given_name: "Toni", family_name: "Bergholm", age_over_18: true } };
  assert.deepEqual(checkDcqlSatisfied(MDOC_CLAIMS, disclosed), []);
});

test("checkDcqlSatisfied: mdoc — missing element → namespaced path returned", () => {
  const disclosed = { "org.iso.18013.5.1": { given_name: "Toni", family_name: "Bergholm" } };
  const missing = checkDcqlSatisfied(MDOC_CLAIMS, disclosed);
  assert.deepEqual(missing, ["org.iso.18013.5.1.age_over_18"]);
});

test("checkDcqlSatisfied: mdoc — entire namespace absent → all paths missing", () => {
  const missing = checkDcqlSatisfied(MDOC_CLAIMS, {});
  assert.deepEqual(missing, [
    "org.iso.18013.5.1.given_name",
    "org.iso.18013.5.1.family_name",
    "org.iso.18013.5.1.age_over_18",
  ]);
});
