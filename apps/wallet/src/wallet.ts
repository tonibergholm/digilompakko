/**
 * Wallet (holder) logic, framework-agnostic so it can be reused by the HTTP layer, a CLI, or tests.
 *
 * Keys live in a `SoftwareKeyStore` (the WSCD boundary abstraction) — the wallet never handles
 * raw private key material, it asks the keystore to sign. Credentials are in-memory for the demo.
 */
import {
  SoftwareKeyStore,
  createPresentation,
  peekPayload,
  pkceS256Challenge,
  ALG,
  type JWK,
  type CredentialOffer,
  type PresentationRequest,
} from "@digilompakko/core";
import { randomUUID } from "node:crypto";

export interface StoredCredential {
  sdJwt: string;
  vct: string;
}

export class Wallet {
  private keyStore = new SoftwareKeyStore();
  private keyId!: string;
  private publicJwk!: JWK;
  readonly credentials: StoredCredential[] = [];

  async init(): Promise<void> {
    const { keyId, publicJwk } = await this.keyStore.generateKey();
    this.keyId = keyId;
    this.publicJwk = publicJwk;
  }

  /** OpenID4VCI pre-authorized code flow. */
  async acceptOffer(offer: CredentialOffer): Promise<StoredCredential> {
    const issuer = offer.credential_issuer;
    const preAuth = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"];
    const token = (await this.postJson(`${issuer}/token`, {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": preAuth,
    })) as TokenResponse;
    return this.fetchCredential(issuer, token);
  }

  /**
   * OpenID4VCI Authorization Code flow with PAR (RFC 9126) + PKCE (RFC 7636).
   * Demonstrates the higher-assurance issuance path the ARF expects for PID.
   */
  async acceptViaAuthCode(issuer: string, clientId = "digilompakko-wallet"): Promise<StoredCredential> {
    const codeVerifier = randomUUID() + randomUUID();
    const codeChallenge = pkceS256Challenge(codeVerifier);

    const par = (await this.postJson(`${issuer}/par`, {
      client_id: clientId,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      scope: "pid",
    })) as { request_uri: string };

    const auth = (await (await fetch(`${issuer}/authorize?request_uri=${encodeURIComponent(par.request_uri)}`)).json()) as { code: string };

    const token = (await this.postJson(`${issuer}/token`, {
      grant_type: "authorization_code",
      code: auth.code,
      code_verifier: codeVerifier,
      client_id: clientId,
    })) as TokenResponse;

    return this.fetchCredential(issuer, token);
  }

  /** Shared: build the holder Proof-of-Possession and call the credential endpoint. */
  private async fetchCredential(issuer: string, token: TokenResponse): Promise<StoredCredential> {
    const signer = this.keyStore.getSigner(this.keyId);
    const proofJwt = await signer.signJwt(
      { alg: ALG, typ: "openid4vci-proof+jwt", jwk: this.publicJwk },
      { iat: Math.floor(Date.now() / 1000), nonce: token.c_nonce, aud: issuer },
    );

    const credRes = await fetch(`${issuer}/credential`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token.access_token}` },
      body: JSON.stringify({ format: "dc+sd-jwt", proof: { proof_type: "jwt", jwt: proofJwt } }),
    });
    const { credential } = (await credRes.json()) as { credential?: string };
    if (!credential) throw new Error("issuer returned no credential");

    const stored: StoredCredential = { sdJwt: credential, vct: peekPayload(credential).vct as string };
    this.credentials.push(stored);
    return stored;
  }

  /** OpenID4VP: fetch the request, build a presentation (signed via the keystore), post the vp_token. */
  async present(requestUri: string, revealOverride?: string[]): Promise<{ requestId: string; result: unknown }> {
    const request = (await (await fetch(requestUri)).json()) as PresentationRequest;

    const wanted = request.dcql_query.credentials[0];
    const cred = this.credentials.find((c) => wanted.meta.vct_values.includes(c.vct));
    if (!cred) throw new Error(`no stored credential matches ${wanted.meta.vct_values.join(",")}`);

    const requested = wanted.claims.map((c) => c.path[0]);
    const toReveal = revealOverride ?? requested;

    const presentation = await createPresentation(
      cred.sdJwt,
      this.keyStore.getSigner(this.keyId), // signs inside the keystore (WSCD)
      toReveal,
      request.client_id,
      request.nonce,
    );

    const responseUri = request.response_uri;
    const postRes = await fetch(responseUri, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ vp_token: presentation }),
    });
    const result = await postRes.json();
    const requestId = new URL(responseUri).searchParams.get("id") ?? "";
    return { requestId, result };
  }

  private async postJson(url: string, body: unknown): Promise<unknown> {
    const res = await fetch(url, {
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
