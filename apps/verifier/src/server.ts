/**
 * OpenID4VP 1.0 verifier (relying party) with trust resolution + revocation checking.
 *
 * Endpoints:
 *   POST /presentation/request        create an Authorization Request (DCQL + nonce)
 *   GET  /presentation/request/:id    wallet fetches the request object
 *   POST /presentation/response       receive vp_token, verify (trust + status), return result
 *   GET  /presentation/result/:id     poll a session result
 *
 * Trust: issuer keys come from a pluggable TrustResolver (here a static allow-list that reads
 * the issuer's published JWKS). Revocation: if the credential carries a `status` reference, the
 * verifier fetches the issuer's Status List Token and rejects revoked credentials.
 */
import express from "express";
import { randomUUID } from "node:crypto";
import {
  verifyPresentation,
  peekPayload,
  readStatus,
  StaticTrustResolver,
  RelyingPartyRegistry,
  STATUS_INVALID,
  Oid4vcError,
  sendError,
  type DcqlQuery,
} from "@digilompakko/core";

const PORT = Number(process.env.VERIFIER_PORT ?? 4002);
const VERIFIER_URL = process.env.VERIFIER_URL ?? `http://localhost:${PORT}`;
// Allow-list of trusted issuers (comma-separated env, or the local demo issuer by default).
const TRUSTED = (process.env.TRUSTED_ISSUERS ?? "http://localhost:4001").split(",").map((s) => s.trim());

const app = express();
app.use(express.json());

const trust = new StaticTrustResolver(TRUSTED);

// This verifier registers itself as a Relying Party, declaring exactly which attributes it is
// entitled to request. The registry gate (assertEntitled) enforces data minimisation: the RP
// cannot ask for more than it registered for. A wallet could resolve /rp/:clientId to verify this.
const REQUESTED_ATTRS = ["given_name", "family_name", "age_over_18"];
const rpRegistry = new RelyingPartyRegistry();
rpRegistry.register({ client_id: VERIFIER_URL, name: "Digilompakko Demo Relying Party", entitled_attributes: REQUESTED_ATTRS });

const DCQL: DcqlQuery = {
  credentials: [
    {
      id: "pid",
      format: "dc+sd-jwt",
      meta: { vct_values: ["eu.europa.ec.eudi.pid.1"] },
      claims: [{ path: ["given_name"] }, { path: ["family_name"] }, { path: ["age_over_18"] }],
    },
  ],
};

interface Session { nonce: string; result?: unknown }
const sessions = new Map<string, Session>();

// RP registration lookup (a wallet can check the verifier is a registered RP).
app.get("/rp/:clientId", (req, res) => {
  const rp = rpRegistry.get(decodeURIComponent(req.params.clientId));
  if (!rp) return res.status(404).json({ error: "not_registered" });
  res.json(rp);
});

app.post("/presentation/request", (_req, res) => {
  try {
    // Data-minimisation gate: refuse to build a request for attributes we are not entitled to.
    rpRegistry.assertEntitled(VERIFIER_URL, REQUESTED_ATTRS);
    const id = randomUUID();
    const nonce = randomUUID();
    sessions.set(id, { nonce });
    res.json({ request_id: id, request_uri: `${VERIFIER_URL}/presentation/request/${id}` });
  } catch (e) {
    sendError(res, e);
  }
});

app.get("/presentation/request/:id", (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: "unknown request" });
  res.json({
    client_id: VERIFIER_URL,
    nonce: session.nonce,
    response_type: "vp_token",
    response_mode: "direct_post",
    response_uri: `${VERIFIER_URL}/presentation/response?id=${req.params.id}`,
    dcql_query: DCQL,
  });
});

app.post("/presentation/response", async (req, res) => {
  try {
    const id = String(req.query.id ?? "");
    const session = sessions.get(id);
    if (!session) throw new Oid4vcError("invalid_request", "unknown presentation session", 404);

    const vpToken: string | undefined = req.body?.vp_token;
    if (!vpToken) throw new Oid4vcError("invalid_presentation", "missing vp_token");

    // 1. Resolve trust: is the issuer on our trusted list? Get its signing key.
    const issuer = peekPayload(vpToken).iss as string;
    const issuerKey = await trust.resolveIssuerKey(issuer);

    // 2. Cryptographic + holder-binding verification.
    const result = await verifyPresentation(vpToken, issuerKey, VERIFIER_URL, session.nonce);

    // 3. Revocation: check the Token Status List if the credential references one.
    if (result.valid) {
      const statusRef = (result.issuerClaims.status as { status_list?: { idx: number; uri: string } } | undefined)?.status_list;
      if (statusRef) {
        const token = await fetch(statusRef.uri).then((r) => r.text());
        const status = await readStatus(token, statusRef.idx, issuerKey);
        if (status === STATUS_INVALID) {
          result.valid = false;
          result.errors.push("credential_revoked");
        }
      }
    }

    session.result = result;
    res.json(result);
  } catch (e) {
    sendError(res, e);
  }
});

app.get("/presentation/result/:id", (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: "unknown request" });
  res.json(session.result ?? { pending: true });
});

app.listen(PORT, () => {
  console.log(`[verifier] OpenID4VP verifier on ${VERIFIER_URL}`);
  console.log(`[verifier] trusted issuers: ${TRUSTED.join(", ")}`);
});
