/**
 * Wallet (holder) logic, framework-agnostic so it can be reused by the HTTP layer, a CLI, or tests.
 *
 * Keys live in a `SoftwareKeyStore` (the WSCD boundary abstraction) — the wallet never handles
 * raw private key material, it asks the keystore to sign. Credentials are in-memory for the demo.
 * Supports both credential formats: SD-JWT VC (`dc+sd-jwt`) and ISO 18013-5 mdoc (`mso_mdoc`).
 */
import {
  SoftwareKeyStore,
  createPresentation,
  createMdocPresentation,
  verifyPresentationRequest,
  peekPayload,
  pkceS256Challenge,
  safeFetch,
  safeFetchJson,
  Oid4vcError,
  ALG,
  type JWK,
  type CredentialOffer,
} from "@digilompakko/core";
import { randomUUID } from "node:crypto";

const MDL_CONFIG_ID = "org.iso.18013.5.1.mDL";

/**
 * Wallet trust configuration.
 *
 * `trustedVerifierOrigins` is a pre-configured allowlist of verifier base URLs.  The wallet will
 * ONLY fetch JWKS from — and accept JARs signed by — verifiers whose `client_id` URL origin
 * exactly matches one of these origins (URL.origin equality, not prefix matching).  This prevents
 * both attacker-controlled JWKS URLs and subdomain-bypass attacks (HIGH-1 / #6 fixes).
 *
 * `walletAudience` is this wallet's own identifier; it must appear in the `aud` claim of every
 * signed request object (RFC 9101 §4).  Agreed out-of-band with each registered verifier.
 */
export interface WalletConfig {
  trustedVerifierOrigins: string[];
  walletAudience: string;
}

export interface StoredCredential {
  format: "dc+sd-jwt" | "mso_mdoc";
  /** SD-JWT VC compact string (format dc+sd-jwt). */
  sdJwt?: string;
  vct?: string;
  /** base64url(CBOR(IssuerSigned)) (format mso_mdoc). */
  mdoc?: string;
  docType?: string;
}

export class Wallet {
  private keyStore = new SoftwareKeyStore();
  private keyId!: string;
  private publicJwk!: JWK;
  readonly credentials: StoredCredential[] = [];
  private readonly config: WalletConfig;

  constructor(config?: WalletConfig) {
    this.config = config ?? {
      trustedVerifierOrigins: [(process.env.VERIFIER_URL ?? "http://localhost:4002")],
      walletAudience: process.env.WALLET_AUDIENCE ?? "digilompakko-wallet",
    };
  }

  async init(): Promise<void> {
    const { keyId, publicJwk } = await this.keyStore.generateKey();
    this.keyId = keyId;
    this.publicJwk = publicJwk;
  }

  /** OpenID4VCI pre-authorized code flow. Format is derived from the offer. */
  async acceptOffer(offer: CredentialOffer): Promise<StoredCredential> {
    const issuer = offer.credential_issuer;
    const configId = offer.credential_configuration_ids[0];
    const preAuth = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"];
    const token = (await this.postJson(`${issuer}/token`, {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": preAuth,
    })) as TokenResponse;
    return this.fetchCredential(issuer, token, this.formatFor(configId));
  }

  /** OpenID4VCI Authorization Code flow with PAR (RFC 9126) + PKCE (RFC 7636). PID only here. */
  async acceptViaAuthCode(issuer: string, clientId = "digilompakko-wallet"): Promise<StoredCredential> {
    const codeVerifier = randomUUID() + randomUUID();
    const codeChallenge = pkceS256Challenge(codeVerifier);

    const par = (await this.postJson(`${issuer}/par`, {
      client_id: clientId,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      scope: "pid",
    })) as { request_uri: string };

    const auth = await safeFetchJson<{ code: string }>(`${issuer}/authorize?request_uri=${encodeURIComponent(par.request_uri)}`);

    const token = (await this.postJson(`${issuer}/token`, {
      grant_type: "authorization_code",
      code: auth.code,
      code_verifier: codeVerifier,
      client_id: clientId,
    })) as TokenResponse;

    return this.fetchCredential(issuer, token, "dc+sd-jwt");
  }

  private formatFor(configId: string): "dc+sd-jwt" | "mso_mdoc" {
    return configId === MDL_CONFIG_ID ? "mso_mdoc" : "dc+sd-jwt";
  }

  /** Shared: build the holder Proof-of-Possession and call the credential endpoint. */
  private async fetchCredential(issuer: string, token: TokenResponse, format: "dc+sd-jwt" | "mso_mdoc"): Promise<StoredCredential> {
    const signer = this.keyStore.getSigner(this.keyId);
    const proofJwt = await signer.signJwt(
      { alg: ALG, typ: "openid4vci-proof+jwt", jwk: this.publicJwk },
      { iat: Math.floor(Date.now() / 1000), nonce: token.c_nonce, aud: issuer },
    );

    const credRes = await safeFetch(`${issuer}/credential`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token.access_token}` },
      body: JSON.stringify({ format, proof: { proof_type: "jwt", jwt: proofJwt } }),
    });
    const data = (await credRes.json()) as { credential?: string; format?: string; doctype?: string };
    if (!data.credential) throw new Error("issuer returned no credential");

    const stored: StoredCredential =
      data.format === "mso_mdoc"
        ? { format: "mso_mdoc", mdoc: data.credential, docType: data.doctype }
        : { format: "dc+sd-jwt", sdJwt: data.credential, vct: peekPayload(data.credential).vct as string };
    this.credentials.push(stored);
    return stored;
  }

  /** OpenID4VP: fetch the request, build a presentation (signed via the keystore), post the vp_token. */
  async present(requestUri: string, revealOverride?: string[]): Promise<{ requestId: string; result: unknown }> {
    const request = await this.resolveRequest(requestUri);
    const vpToken =
      request.format === "mso_mdoc"
        ? await this.buildMdocPresentation(request, revealOverride)
        : await this.buildSdJwtPresentation(request, revealOverride);

    // OID4VP §6.2: response_uri MUST share origin with client_id to prevent PII exfiltration.
    if (new URL(request.response_uri).origin !== new URL(request.client_id).origin) {
      throw new Oid4vcError(
        "invalid_request",
        "response_uri origin does not match client_id origin",
      );
    }

    const postRes = await safeFetch(request.response_uri, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ vp_token: vpToken }),
    });
    const result = await postRes.json();
    const requestId = new URL(request.response_uri).searchParams.get("id") ?? "";
    return { requestId, result };
  }

  /**
   * Fetch the verifier's signed request object (JAR) and verify it fully before trusting anything.
   *
   * HIGH-1 fix — two properties enforced here:
   *   a) Unsigned requests are rejected outright (no legacy bypass).  HAIP requires JAR.
   *   b) The JWKS URL is derived from `trustedVerifierOrigins`, not from attacker-controlled claims.
   *      We peek `client_id` only to look it up in our pre-configured trust list; if the origin
   *      is not trusted we throw before making any network request to that origin.
   *
   * Verification of typ / exp / aud is delegated to verifyPresentationRequest in packages/core.
   */
  private async resolveRequest(requestUri: string): Promise<PresentationRequestObject> {
    const raw = await safeFetchJson<{ request?: string } & PresentationRequestObject>(requestUri);

    // RFC 9101 §4 + HAIP: unsigned requests MUST be rejected — no legacy bypass.
    if (!raw.request) {
      throw new Oid4vcError("invalid_request", "unsigned presentation request rejected (JAR required by HAIP)");
    }

    // Peek client_id before any cryptographic trust is granted (payload not yet verified).
    const clientId = peekPayload(raw.request).client_id as string | undefined;
    if (!clientId) throw new Oid4vcError("invalid_request", "request object missing client_id");

    // Trust gate: only proceed if the client_id origin exactly matches one in our pre-configured allowlist.
    // URL.origin equality prevents startsWith bypass (e.g. http://localhost:4002.evil.com passing
    // when allowlist contains http://localhost:4002).
    const clientOrigin = new URL(clientId).origin;
    const trustedOrigin = this.config.trustedVerifierOrigins.find(
      (o) => new URL(o).origin === clientOrigin,
    );
    if (!trustedOrigin) {
      throw new Oid4vcError("access_denied", `untrusted verifier origin: ${clientId}`, 403);
    }

    // Fetch JWKS from the trusted origin (safe URL — derived from our config, not the JWT).
    const jwks = (await (await safeFetch(`${trustedOrigin}/jwks.json`)).json()) as { keys: JWK[] };
    if (!jwks.keys?.length) throw new Oid4vcError("invalid_request", "verifier JWKS is empty");
    const trustedRps = new Map<string, JWK>([[clientId, jwks.keys[0]]]);

    return (await verifyPresentationRequest(raw.request, trustedRps, {
      expectedAudience: this.config.walletAudience,
    })) as unknown as PresentationRequestObject;
  }

  private async buildSdJwtPresentation(request: PresentationRequestObject, revealOverride?: string[]): Promise<string> {
    const wanted = request.dcql_query.credentials[0];
    const cred = this.credentials.find((c) => c.format === "dc+sd-jwt" && wanted.meta.vct_values?.includes(c.vct!));
    if (!cred?.sdJwt) throw new Error("no matching SD-JWT VC credential stored");
    const toReveal = revealOverride ?? wanted.claims.map((c) => c.path[c.path.length - 1]);
    return createPresentation(cred.sdJwt, this.keyStore.getSigner(this.keyId), toReveal, request.client_id, request.nonce);
  }

  private async buildMdocPresentation(request: PresentationRequestObject, revealOverride?: string[]): Promise<string> {
    const wanted = request.dcql_query.credentials[0];
    const cred = this.credentials.find((c) => c.format === "mso_mdoc" && c.docType === wanted.meta.doctype_value);
    if (!cred?.mdoc || !cred.docType) throw new Error("no matching mdoc credential stored");

    // DCQL mdoc claim paths are [namespace, element]. Group requested elements per namespace.
    const reveal: Record<string, string[]> = {};
    for (const c of wanted.claims) {
      const [ns, element] = c.path;
      if (revealOverride && !revealOverride.includes(element)) continue;
      (reveal[ns] ??= []).push(element);
    }
    return createMdocPresentation(
      { docType: cred.docType, issuerSigned: cred.mdoc },
      this.keyStore.getSigner(this.keyId),
      reveal,
      request.client_id,
      request.nonce,
    );
  }

  private async postJson(url: string, body: unknown): Promise<unknown> {
    const res = await safeFetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return res.json();
  }

  get holderPublicJwk(): JWK {
    return this.publicJwk;
  }
}

interface TokenResponse {
  access_token: string;
  c_nonce: string;
}

/** The verifier's request object (covers both SD-JWT VC and mdoc DCQL shapes). */
interface PresentationRequestObject {
  client_id: string;
  nonce: string;
  response_uri: string;
  format?: "dc+sd-jwt" | "mso_mdoc";
  dcql_query: {
    credentials: Array<{
      id: string;
      format: string;
      meta: { vct_values?: string[]; doctype_value?: string };
      claims: Array<{ path: string[] }>;
    }>;
  };
}
