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

const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
if (!ADMIN_TOKEN) throw new Error("ADMIN_TOKEN env var is required");

function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const auth = req.headers["authorization"];
  if (auth !== `Bearer ${ADMIN_TOKEN}`) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
}

// --- Issuer signing key (generated at startup; published via JWKS) ---
const issuerKeys = await generateP256KeyPair();

// --- Status list (one shared list for the demo) ---
const statusList = new StatusList(1024);
let nextStatusIdx = 0;
interface IssuedRecord { idx: number; subject: string; issuedAt: number }
const issuedRecords: IssuedRecord[] = [];

// --- In-memory issuance stores ---
// A Pending records which credential configuration the holder is being issued.
// `issuedAt` is set when /token issues the access_token + c_nonce; used to enforce both TTLs.
interface Pending { configId: string; cNonce?: string; accessToken?: string; issuedAt?: number; createdAt?: number }
const offers = new Map<string, Pending>();             // pre-authorized_code -> pending
const accessTokens = new Map<string, Pending>();        // access_token -> pending
// Authorization Code flow (RFC 9126 PAR + RFC 7636 PKCE):
interface ParRequest { clientId: string; codeChallenge: string; scope?: string; createdAt: number }
const parRequests = new Map<string, ParRequest>();      // request_uri -> PAR
const authCodes = new Map<string, { codeChallenge: string; clientId: string; pending: Pending; createdAt: number }>(); // code -> ...

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

// Server-side TTL enforcement for all short-lived tokens (OpenID4VCI §7.2, RFC 6749 §4.1.2).
// These MUST match (or be tighter than) the `expires_in` / `c_nonce_expires_in` values emitted
// in token responses so that clients never hold a token they believe is valid but the server rejects.
const ACCESS_TOKEN_TTL_MS = 5 * 60 * 1000; // 300 s — matches expires_in in /token response
const C_NONCE_TTL_MS = 5 * 60 * 1000;      // 300 s — matches c_nonce_expires_in in /token response
const AUTH_CODE_TTL_MS = 60 * 1000;         // 60 s  — RFC 6749 §4.1.2: short-lived auth codes
const PAR_TTL_MS = 90 * 1000;               // 90 s  — matches expires_in in /par response
// OpenID4VCI §4.1.1: pre-authorized codes MUST be short-lived and single-use; 30 s is tight
// enough to prevent offline brute-force while still giving the wallet time to exchange the code.
const PRE_AUTH_CODE_TTL_MS = 30_000;        // 30 s  (#11)

// --- In-memory store size cap and periodic TTL sweep (finding #10) ---
// Prevents unbounded Map growth from unauthenticated offer/PAR/authorize endpoints.
const MAX_MAP_SIZE = 10_000;

function sweepIssuer(): void {
  const now = Date.now();
  for (const [k, v] of offers) {
    if (now - (v.createdAt ?? 0) > PRE_AUTH_CODE_TTL_MS) offers.delete(k);
  }
  for (const [k, v] of parRequests) {
    if (now - (v.createdAt ?? 0) > PAR_TTL_MS) parRequests.delete(k);
  }
  for (const [k, v] of authCodes) {
    if (now - (v.createdAt ?? 0) > AUTH_CODE_TTL_MS) authCodes.delete(k);
  }
  for (const [k, v] of accessTokens) {
    if (now - (v.issuedAt ?? 0) > 300_000) accessTokens.delete(k);
  }
}
setInterval(sweepIssuer, 60_000).unref();

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
    if (offers.size >= MAX_MAP_SIZE) {
      return res.status(429).json({ error: "too_many_requests" });
    }
    const preAuthCode = randomUUID();
    offers.set(preAuthCode, { configId, createdAt: Date.now() });
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
    if (parRequests.size >= MAX_MAP_SIZE) {
      return res.status(429).json({ error: "too_many_requests" });
    }
    const requestUri = `urn:ietf:params:oauth:request_uri:${randomUUID()}`;
    parRequests.set(requestUri, { clientId: client_id, codeChallenge: code_challenge, scope, createdAt: Date.now() });
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
    // RFC 9126 §2.3: the request_uri MUST expire after the advertised `expires_in` seconds.
    if (Date.now() - par.createdAt > PAR_TTL_MS) {
      parRequests.delete(requestUri);
      throw new Oid4vcError("invalid_request", "request_uri expired");
    }
    if (authCodes.size >= MAX_MAP_SIZE) {
      return res.status(429).json({ error: "too_many_requests" });
    }
    const code = randomUUID();
    // RFC 7636 §4.5 + RFC 9126 §2.1: bind the code to both the PKCE challenge and the
    // client_id from PAR so that an intercepted code cannot be redeemed by a different client.
    authCodes.set(code, { codeChallenge: par.codeChallenge, clientId: par.clientId, pending: { configId: PID_CONFIG_ID }, createdAt: Date.now() });
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
      // RFC 6749 §4.1.2: authorization codes MUST be short-lived and single-use.
      if (Date.now() - entry.createdAt > AUTH_CODE_TTL_MS) {
        authCodes.delete(code);
        throw new Oid4vcError("invalid_grant", "authorization code expired");
      }
      // RFC 6749 §10.6 + RFC 9126 §2.1: the client_id presented at the token endpoint MUST
      // match the client_id that obtained the authorization code, preventing code injection by
      // a different client even when PKCE is satisfied.
      if (req.body?.client_id !== entry.clientId) {
        authCodes.delete(code);
        throw new Oid4vcError("invalid_grant", "client_id mismatch");
      }
      verifyPkce(req.body?.code_verifier, entry.codeChallenge); // throws on mismatch
      authCodes.delete(code);
      pending = entry.pending;
    } else {
      const code = req.body?.["pre-authorized_code"];
      pending = code ? offers.get(code) : undefined;
      // OpenID4VCI §4.1.1: pre-authorized codes are single-use and short-lived.
      // Delete before TTL check so an expired code cannot be retried by the same request.
      if (code) offers.delete(code);
      if (!pending || Date.now() - (pending.createdAt ?? 0) > PRE_AUTH_CODE_TTL_MS) {
        throw new Oid4vcError("invalid_grant", "pre-authorized_code expired or unknown");
      }
    }

    const accessToken = randomUUID();
    const cNonce = randomUUID();
    pending.accessToken = accessToken;
    pending.cNonce = cNonce;
    // Record issuance time; used to enforce both the access-token TTL and the c_nonce TTL.
    // OpenID4VCI §7.2: c_nonce_expires_in informs the wallet when to refresh the nonce.
    pending.issuedAt = Date.now();
    if (accessTokens.size >= MAX_MAP_SIZE) {
      return res.status(429).json({ error: "too_many_requests" });
    }
    accessTokens.set(accessToken, pending);
    res.json({ access_token: accessToken, token_type: "bearer", expires_in: 300, c_nonce: cNonce, c_nonce_expires_in: 300 });
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
    // RFC 6749 §5.1: enforce the advertised access-token lifetime (expires_in: 300).
    if (Date.now() - (pending.issuedAt ?? 0) > ACCESS_TOKEN_TTL_MS) {
      accessTokens.delete(accessToken);
      throw new Oid4vcError("invalid_token", "access token expired", 401);
    }

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
      // OpenID4VCI §7.2: the c_nonce is valid only for c_nonce_expires_in seconds.
      if (Date.now() - (pending.issuedAt ?? 0) > C_NONCE_TTL_MS) throw new Error("c_nonce expired");
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

// 6) Admin: revoke a credential by its status index — requires Bearer ADMIN_TOKEN (#3).
app.post("/admin/revoke", requireAdmin, (req, res) => {
  try {
    const idx = Number(req.body?.idx);
    if (!Number.isInteger(idx)) throw new Oid4vcError("invalid_request", "idx must be an integer");
    statusList.set(idx, STATUS_INVALID);
    res.json({ ok: true, idx, status: "revoked" });
  } catch (e) {
    sendError(res, e);
  }
});

// 7) Admin: list issued records — requires Bearer ADMIN_TOKEN (#3).
app.get("/admin/issued", requireAdmin, (_req, res) => res.json(issuedRecords));

app.listen(PORT, () => console.log(`[issuer]   OpenID4VCI issuer + status list on ${ISSUER_URL}`));
