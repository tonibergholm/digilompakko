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
  generateP256KeyPair,
  verifyPresentation,
  verifyMdocPresentation,
  peekPayload,
  readStatus,
  signRequestObject,
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

// Verifier (RP) signing key for signed request objects (JAR). Published at /jwks.json so the
// wallet can verify the request genuinely came from this RP before disclosing anything.
const verifierKeys = await generateP256KeyPair();

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

// mdoc (mso_mdoc) DCQL: claims are namespace-qualified per ISO 18013-5.
const MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
const MDL_NAMESPACE = "org.iso.18013.5.1";
const DCQL_MDL = {
  credentials: [
    {
      id: "mdl",
      format: "mso_mdoc",
      meta: { doctype_value: MDL_DOCTYPE },
      claims: [
        { path: [MDL_NAMESPACE, "given_name"] },
        { path: [MDL_NAMESPACE, "family_name"] },
        { path: [MDL_NAMESPACE, "age_over_18"] },
      ],
    },
  ],
};

type Format = "dc+sd-jwt" | "mso_mdoc";
interface Session {
  nonce: string;
  format: Format;
  /** Epoch ms when the session was created — used to enforce SESSION_TTL_MS. */
  createdAt: number;
  /** True once a vp_token has been accepted for this session. Any further submission is replay. */
  consumed: boolean;
  result?: unknown;
}
// OpenID4VP §6.2: the verifier MUST ensure each nonce is used only once.  A session that has
// already received a valid vp_token, or that was created more than SESSION_TTL_MS ago, is refused.
const SESSION_TTL_MS = 5 * 60 * 1000; // 5 minutes
const sessions = new Map<string, Session>();

// Verifier (RP) public key — the wallet verifies signed request objects against this.
app.get("/jwks.json", (_req, res) => res.json({ keys: [verifierKeys.publicJwk] }));

// RP registration lookup (a wallet can check the verifier is a registered RP).
app.get("/rp/:clientId", (req, res) => {
  const rp = rpRegistry.get(decodeURIComponent(req.params.clientId));
  if (!rp) return res.status(404).json({ error: "not_registered" });
  res.json(rp);
});

app.post("/presentation/request", (req, res) => {
  try {
    // Data-minimisation gate: refuse to build a request for attributes we are not entitled to.
    rpRegistry.assertEntitled(VERIFIER_URL, REQUESTED_ATTRS);
    const format: Format = req.query.format === "mso_mdoc" ? "mso_mdoc" : "dc+sd-jwt";
    const id = randomUUID();
    const nonce = randomUUID();
    sessions.set(id, { nonce, format, createdAt: Date.now(), consumed: false });
    res.json({ request_id: id, request_uri: `${VERIFIER_URL}/presentation/request/${id}` });
  } catch (e) {
    sendError(res, e);
  }
});

app.get("/presentation/request/:id", async (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: "unknown request" });
  const requestObject = {
    client_id: VERIFIER_URL,
    nonce: session.nonce,
    response_type: "vp_token",
    response_mode: "direct_post",
    response_uri: `${VERIFIER_URL}/presentation/response?id=${req.params.id}`,
    format: session.format,
    dcql_query: session.format === "mso_mdoc" ? DCQL_MDL : DCQL,
  };
  // Signed request object (JAR): the wallet verifies our signature before responding.
  const request = await signRequestObject(verifierKeys.privateJwk, requestObject);
  res.json({ request });
});

app.post("/presentation/response", async (req, res) => {
  try {
    const id = String(req.query.id ?? "");
    const session = sessions.get(id);
    if (!session) throw new Oid4vcError("invalid_request", "unknown presentation session", 404);

    // --- Replay and expiry checks (synchronous, before any await) ---
    // Setting consumed=true before the first await is intentional: in Node.js a single-threaded
    // event loop can interleave two concurrent POSTs at every await point.  By mutating the flag
    // synchronously we make the "check + mark" atomic with respect to the event loop.
    // OpenID4VP §6.2 / HAIP: a nonce MUST NOT be reused across presentations.
    if (Date.now() - session.createdAt > SESSION_TTL_MS) {
      sessions.delete(id);
      throw new Oid4vcError("invalid_request", "presentation session expired");
    }
    if (session.consumed) {
      throw new Oid4vcError("invalid_request", "presentation session already used (replay rejected)");
    }

    const vpToken: string | undefined = req.body?.vp_token;
    if (!vpToken) throw new Oid4vcError("invalid_presentation", "missing vp_token");

    // Consume the session atomically before yielding to any async work.
    session.consumed = true;

    // --- mdoc (mso_mdoc) path: the DeviceResponse carries no issuer URL, so we resolve the
    //     issuer key from our trusted issuer's metadata. (A full 18013-5 flow uses the issuerAuth
    //     x5chain instead.) No Token Status List in this mdoc subset — see ROADMAP.
    if (session.format === "mso_mdoc") {
      const issuerKey = await trust.resolveIssuerKey(TRUSTED[0]);
      const mResult = await verifyMdocPresentation(vpToken, issuerKey, VERIFIER_URL, session.nonce);
      // Revocation: if the MSO carries a status reference, check the Token Status List.
      if (mResult.valid && mResult.status) {
        const token = await fetch(mResult.status.uri).then((r) => r.text());
        const status = await readStatus(token, mResult.status.idx, issuerKey);
        if (status === STATUS_INVALID) {
          mResult.valid = false;
          mResult.errors.push("credential_revoked");
        }
      }
      session.result = mResult;
      return res.json(mResult);
    }

    // --- SD-JWT VC path ---
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
