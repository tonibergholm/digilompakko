/**
 * DCQL (Digital Credentials Query Language) enforcement.
 *
 * The verifier sends a DCQL query telling the wallet which claims to disclose.  After receiving
 * the vp_token the verifier MUST validate that the disclosed claims actually satisfy the query —
 * a wallet that discloses nothing (or the wrong claims) must be rejected.
 *
 * DCQL draft §6.3: "the Verifier MUST verify that the Credential received in the VP Token
 * satisfies the Credential Query it sent."
 */

/**
 * Check that every claim path requested in a DCQL credential query is present in the disclosed
 * claims map.  Returns an array of dot-joined missing paths (empty → fully satisfied).
 *
 * The `path` arrays follow JSON-Path-style navigation over `disclosedClaims`:
 *   SD-JWT VC flat:  path=["given_name"]          → disclosedClaims["given_name"]
 *   mdoc namespaced: path=["org.iso.18013.5.1","age_over_18"]
 *                                                  → disclosedClaims["org.iso.18013.5.1"]["age_over_18"]
 *
 * A claim is considered satisfied when the path resolves to a non-null, non-undefined value.
 * `false`, `0`, and `""` are valid disclosed values.
 */
export function checkDcqlSatisfied(
  requestedClaims: Array<{ path: string[] }>,
  disclosedClaims: Record<string, unknown>,
): string[] {
  const missing: string[] = [];
  for (const { path } of requestedClaims) {
    let cur: unknown = disclosedClaims;
    for (const key of path) {
      if (cur == null || typeof cur !== "object") { cur = undefined; break; }
      cur = (cur as Record<string, unknown>)[key];
    }
    if (cur == null) missing.push(path.join("."));
  }
  return missing;
}
