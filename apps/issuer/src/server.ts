/**
 * OpenID4VCI 1.0 issuer (PID provider) — pre-authorized code flow + Token Status List.
 *
 * Endpoints (each maps to an OpenID4VCI / Status List clause):
 *   GET  /.well-known/openid-credential-issuer   issuer metadata + JWKS
 *   POST /offer                                   create a Credential Offer (demo helper)
 *   POST /token                                   pre-auth code -> access_token + c_nonce
 *   POST /credential                              verify holder PoP -> SD-JWT VC (with status)
 *   GET  /statuslist                              signed Status List Token (statuslist+jwt)
 *   POST /admin/revoke                            { idx } -> mark a credential revoked (demo admin)
 *
 * NOTE: in-memory state, software keys — demo only. See docs/COMPLIANCE.md §6.
 */
import express from "express";
import { randomUUID } from "node:crypto";
import { importJWK, jwtVerify, type JWK } from "jose";
import {
  generateP256KeyPair,
  issueSdJwtVc,
  issueMdoc,
  StatusList,
  buildStatusListToken,
  STATUS_INVALID,
  Oid4vcError,
  sendError,
  verifyPkce,
  ALG,
  type CredentialClaims,
  type MdocClaims,
} from "@digilompakko/core";

const PORT = Number(process.env.ISSUER_PORT ?? 4001);
const ISSUER_URL = process.env.ISSUER_URL ?? `http://localhost:${PORT}`;
const STATUS_URI = `${ISSUER_URL}/statuslist`;
const PID_CONFIG_ID = "eu.europa.ec.eudi.pid.1";
const MDL_CONFIG_ID = "org.iso.18013.5.1.mDL";
const MDL_NAMESPACE = "org.iso.18013.5.1";

const app = express();
app.use(express.json());

// --- Issuer signing key (generated at startup; published via JWKS) ---
const issuerKeys = await generateP256KeyPair();

// --- Status list (one shared list for the demo) ---
const statusList = new StatusList(1024);
let nextStatusIdx = 0;
interface IssuedRecord { idx: number; subject: string; issuedAt: number }
const issuedRecords: IssuedRecord[] = [];

// --- In-memory issuance stores ---
// A Pending records which credential configuration the holder is being issued.
interface Pending { configId: string; cNonce?: string; accessToken?: string }
const offers = new Map<string, Pending>();             // pre-authorized_code -> pending
const accessTokens = new Map<string, Pending>();        // access_token -> pending
// Authorization Code flow (RFC 9126 PAR + RFC 7636 PKCE):
interface ParRequest { clientId: string; codeChallenge: string; scope?: string }
const parRequests = new Map<string, ParRequest>();      // request_uri -> PAR
const authCodes = new Map<string, { codeChallenge: string; pending: Pending }>(); // code -> ...

const DEMO_PID: CredentialClaims = {
  vct: PID_CONFIG_ID,
  claims: {
    given_name: "Toni",
    family_name: "Bergholm",
    birthdate: "1985-04-12",
    nationality: "FI",
    age_over_18: true,
  },
  alwaysDisclosed: { issuing_country: "FI", issuing_authority: "DVV (demo)" },
  expiresInSeconds: 60 * 60 * 24 * 365,
};

const DEMO_MDL: MdocClaims = {
  docType: MDL_CONFIG_ID,
  namespaces: {
    [MDL_NAMESPACE]: {
      family_name: "Bergholm",
      given_name: "Toni",
      birth_date: "1985-04-12",
      document_number: "X1234567",
      issuing_country: "FI",
      age_over_18: true,
    },
  },
};

const SUPPORTED_CONFIGS = new Set([PID_CONFIG_ID, MDL_CONFIG_ID]);

// 1) Issuer metadata
app.get("/.well-known/openid-credential-issuer", (_req, res) => {
  res.json({
    credential_issuer: ISSUER_URL,
    credential_endpoint: `${ISSUER_URL}/credential`,
    token_endpoint: `${ISSUER_URL}/token`,
    authorization_endpoint: `${ISSUER_URL}/authorize`,
    pushed_authorization_request_endpoint: `${ISSUER_URL}/par`,
    status_list_endpoint: STATUS_URI,
    jwks: { keys: [issuerKeys.publicJwk] },
    credential_configurations_supported: {
      [PID_CONFIG_ID]: {
        format: "dc+sd-jwt",
        vct: PID_CONFIG_ID,
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: [ALG],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: [ALG] } },
      },
      // Format negotiation: the same issuer also advertises an ISO 18013-5 mDL (mso_mdoc).
      "org.iso.18013.5.1.mDL": {
        format: "mso_mdoc",
        doctype: "org.iso.18013.5.1.mDL",
        cryptographic_binding_methods_supported: ["cose_key"],
        credential_signing_alg_values_supported: [ALG],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: [ALG] } },
      },
    },
  });
});

// 2) Create a Credential Offer (pre-authorized code flow). Optional body
//    { credential_configuration_id } selects PID (default) or the mDL.
app.post("/offer", (req, res) => {
  try {
    const configId = req.body?.credential_configuration_id ?? PID_CONFIG_ID;
    if (!SUPPORTED_CONFIGS.has(configId)) throw new Oid4vcError("invalid_request", `unknown configuration: ${configId}`);
    const preAuthCode = randomUUID();
    offers.set(preAuthCode, { configId });
    res.json({
      credential_issuer: ISSUER_URL,
      credential_configuration_ids: [configId],
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": preAuthCode },
      },
    });
  } catch (e) {
    sendError(res, e);
  }
});

// 3a) Pushed Authorization Request (RFC 9126) — start of the Authorization Code flow.
app.post("/par", (req, res) => {
  try {
    const { client_id, code_challenge, code_challenge_method, scope } = req.body ?? {};
    if (!client_id) throw new Oid4vcError("invalid_request", "missing client_id");
    if (code_challenge_method !== "S256") throw new Oid4vcError("invalid_request", "code_challenge_method must be S256");
    if (!code_challenge) throw new Oid4vcError("invalid_request", "missing code_challenge");
    const requestUri = `urn:ietf:params:oauth:request_uri:${randomUUID()}`;
    parRequests.set(requestUri, { clientId: client_id, codeChallenge: code_challenge, scope });
    res.json({ request_uri: requestUri, expires_in: 90 });
  } catch (e) {
    sendError(res, e);
  }
});

// 3b) Authorization endpoint. A real issuer authenticates the user here (eID); the demo
// auto-approves and returns an authorization code bound to the PAR's PKCE challenge.
app.get("/authorize", (req, res) => {
  try {
    const requestUri = String(req.query.request_uri ?? "");
    const par = parRequests.get(requestUri);
    if (!par) throw new Oid4vcError("invalid_request", "unknown or expired request_uri");
    const code = randomUUID();
    authCodes.set(code, { codeChallenge: par.codeChallenge, pending: { configId: PID_CONFIG_ID } });
    parRequests.delete(requestUri);
    // A real flow redirects to the wallet's redirect_uri with ?code=…; the demo returns JSON.
    res.json({ code });
  } catch (e) {
    sendError(res, e);
  }
});

// 3c) Token endpoint — supports both pre-authorized_code and authorization_code (PKCE) grants.
app.post("/token", (req, res) => {
  try {
    const grant = req.body?.grant_type;
    let pending: Pending | undefined;

    if (grant === "authorization_code") {
      const code = req.body?.code;
      const entry = code ? authCodes.get(code) : undefined;
      if (!entry) throw new Oid4vcError("invalid_grant", "unknown authorization code");
      verifyPkce(req.body?.code_verifier, entry.codeChallenge); // throws on mismatch
      authCodes.delete(code);
      pending = entry.pending;
    } else {
      const code = req.body?.["pre-authorized_code"];
      pending = code ? offers.get(code) : undefined;
      if (!pending) throw new Oid4vcError("invalid_grant", "unknown or used pre-authorized_code");
      offers.delete(code);
    }

    const accessToken = randomUUID();
    const cNonce = randomUUID();
    pending.accessToken = accessToken;
    pending.cNonce = cNonce;
    accessTokens.set(accessToken, pending);
    res.json({ access_token: accessToken, token_type: "bearer", expires_in: 300, c_nonce: cNonce });
  } catch (e) {
    sendError(res, e);
  }
});

// 4) Credential endpoint — verify holder PoP, assign a status index, then issue.
app.post("/credential", async (req, res) => {
  try {
    const accessToken = (req.header("authorization") ?? "").replace(/^Bearer\s+/i, "");
    const pending = accessTokens.get(accessToken);
    if (!pending) throw new Oid4vcError("invalid_token", "unknown access token", 401);

    const proofJwt: string | undefined = req.body?.proof?.jwt;
    if (!proofJwt) throw new Oid4vcError("invalid_proof", "missing proof.jwt");

    // Verify holder Proof-of-Possession (key in JWT header, bound to c_nonce + audience).
    let holderJwk: JWK;
    try {
      const header = JSON.parse(Buffer.from(proofJwt.split(".")[0], "base64url").toString("utf8"));
      holderJwk = header.jwk;
      if (!holderJwk) throw new Error("no jwk in proof header");
      const key = await importJWK(holderJwk, ALG);
      const { payload } = await jwtVerify(proofJwt, key, { typ: "openid4vci-proof+jwt" });
      if (payload.nonce !== pending.cNonce) throw new Error("c_nonce mismatch");
      if (payload.aud !== ISSUER_URL) throw new Error("aud mismatch");
    } catch (e) {
      throw new Oid4vcError("invalid_proof", (e as Error).message);
    }

    // mDL (mso_mdoc): issue an ISO 18013-5 mdoc bound to the holder's device key, with a
    // Token Status List reference in the MSO so it can be revoked (parity with PID).
    if (pending.configId === MDL_CONFIG_ID) {
      const idx = nextStatusIdx++;
      const mdoc = await issueMdoc(issuerKeys.privateJwk, holderJwk, { ...DEMO_MDL, status: { idx, uri: STATUS_URI } });
      issuedRecords.push({ idx, subject: "mDL", issuedAt: Date.now() });
      accessTokens.delete(accessToken);
      return res.json({ credential: mdoc.issuerSigned, format: "mso_mdoc", doctype: mdoc.docType, status_index: idx });
    }

    // PID (SD-JWT VC): assign a Token Status List entry so it can later be revoked.
    const claims = structuredClone(DEMO_PID);
    const idx = nextStatusIdx++;
    issuedRecords.push({ idx, subject: String(claims.claims.family_name ?? "unknown"), issuedAt: Date.now() });
    claims.alwaysDisclosed = { ...claims.alwaysDisclosed, status: { status_list: { idx, uri: STATUS_URI } } };

    const issued = await issueSdJwtVc(issuerKeys.privateJwk, ISSUER_URL, holderJwk, claims);

    accessTokens.delete(accessToken);
    res.json({ credential: issued.sdJwt, format: "dc+sd-jwt", status_index: idx });
  } catch (e) {
    sendError(res, e);
  }
});

// 5) Status List Token endpoint.
app.get("/statuslist", async (_req, res) => {
  const token = await buildStatusListToken(issuerKeys.privateJwk, ISSUER_URL, STATUS_URI, statusList);
  res.type("application/statuslist+jwt").send(token);
});

// 6) Admin: revoke a credential by its status index (demo only — no auth).
app.post("/admin/revoke", (req, res) => {
  try {
    const idx = Number(req.body?.idx);
    if (!Number.isInteger(idx)) throw new Oid4vcError("invalid_request", "idx must be an integer");
    statusList.set(idx, STATUS_INVALID);
    res.json({ ok: true, idx, status: "revoked" });
  } catch (e) {
    sendError(res, e);
  }
});

// 7) Admin: list issued records (demo helper).
app.get("/admin/issued", (_req, res) => res.json(issuedRecords));

app.listen(PORT, () => console.log(`[issuer]   OpenID4VCI issuer + status list on ${ISSUER_URL}`));
