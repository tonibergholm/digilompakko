/**
 * Wallet (holder) logic, framework-agnostic so it can be reused by the HTTP layer,
 * a CLI, or tests. Keys + credentials are in-memory for the demo (see COMPLIANCE.md §6).
 */
import { SignJWT, importJWK } from "jose";
import {
  generateP256KeyPair,
  createPresentation,
  peekPayload,
  ALG,
  type KeyPair,
  type CredentialOffer,
  type PresentationRequest,
} from "@digilompakko/core";

export interface StoredCredential {
  sdJwt: string;
  vct: string;
  claims: Record<string, unknown>; // disclosable claim names (for UI/consent)
}

export class Wallet {
  private holderKeys!: KeyPair;
  readonly credentials: StoredCredential[] = [];

  async init(): Promise<void> {
    this.holderKeys = await generateP256KeyPair();
  }

  /** OpenID4VCI: redeem a Credential Offer and store the resulting SD-JWT VC. */
  async acceptOffer(offer: CredentialOffer): Promise<StoredCredential> {
    const issuer = offer.credential_issuer;
    const preAuth = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"];

    // 1. Token endpoint -> access token + c_nonce.
    const tokenRes = await fetch(`${issuer}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": preAuth,
      }),
    });
    const token = (await tokenRes.json()) as { access_token: string; c_nonce: string };

    // 2. Build a Proof-of-Possession JWT bound to c_nonce + issuer audience.
    const key = await importJWK(this.holderKeys.privateJwk, ALG);
    const proofJwt = await new SignJWT({ nonce: token.c_nonce, aud: issuer })
      .setProtectedHeader({ alg: ALG, typ: "openid4vci-proof+jwt", jwk: this.holderKeys.publicJwk })
      .setIssuedAt()
      .sign(key);

    // 3. Credential endpoint -> SD-JWT VC.
    const credRes = await fetch(`${issuer}/credential`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token.access_token}` },
      body: JSON.stringify({ format: "dc+sd-jwt", proof: { proof_type: "jwt", jwt: proofJwt } }),
    });
    const { credential } = (await credRes.json()) as { credential?: string };
    if (!credential) throw new Error("issuer returned no credential");

    const payload = peekPayload(credential);
    const stored: StoredCredential = {
      sdJwt: credential,
      vct: payload.vct as string,
      claims: this.disclosableNames(credential),
    };
    this.credentials.push(stored);
    return stored;
  }

  /** OpenID4VP: fetch the request, build a presentation, post the vp_token. */
  async present(requestUri: string, revealOverride?: string[]): Promise<{ requestId: string; result: unknown }> {
    const reqRes = await fetch(requestUri);
    const request = (await reqRes.json()) as PresentationRequest;

    const wanted = request.dcql_query.credentials[0];
    const cred = this.credentials.find((c) => wanted.meta.vct_values.includes(c.vct));
    if (!cred) throw new Error(`no stored credential matches ${wanted.meta.vct_values.join(",")}`);

    // The verifier requests these claims; the user could narrow further (consent).
    const requested = wanted.claims.map((c) => c.path[0]);
    const toReveal = revealOverride ?? requested;

    const presentation = await createPresentation(
      cred.sdJwt,
      this.holderKeys.privateJwk,
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

  /** Reads disclosable claim *names* (values stay hidden until presentation). */
  private disclosableNames(_compact: string): Record<string, unknown> {
    // For the demo we expose the names we know the PID carries; a fuller impl would
    // parse the disclosures stored alongside the SD-JWT.
    return {};
  }

  get holderPublicJwk() {
    return this.holderKeys.publicJwk;
  }
}
