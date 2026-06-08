/**
 * Shared types for the Digilompakko EUDI demo.
 * Names follow the OpenID4VCI/VP and SD-JWT VC specifications where possible.
 */
import type { JWK } from "jose";
export type { JWK } from "jose";

/** HAIP mandates the ES256 / P-256 suite. */
export const ALG = "ES256" as const;
export const CRV = "P-256" as const;

/** SD-JWT VC media type (IETF draft-ietf-oauth-sd-jwt-vc). */
export const SD_JWT_VC_TYP = "dc+sd-jwt" as const;

export interface KeyPair {
  publicJwk: JWK;
  privateJwk: JWK;
}

/** A credential as the issuer defines it before selective-disclosure encoding. */
export interface CredentialClaims {
  /** SD-JWT VC type, e.g. "eu.europa.ec.eudi.pid.1". */
  vct: string;
  /** Flat claims; every entry here becomes a selectively-disclosable claim. */
  claims: Record<string, unknown>;
  /** Optional non-disclosable (always-visible) claims merged into the payload. */
  alwaysDisclosed?: Record<string, unknown>;
  /** Seconds until expiry. */
  expiresInSeconds?: number;
}

/** Result of issuing: the compact SD-JWT VC string and a parsed view. */
export interface IssuedCredential {
  /** Compact form: <jws>~<disclosure>~...~  (trailing tilde, no KB-JWT yet). */
  sdJwt: string;
  vct: string;
}

/** OpenID4VCI Credential Offer (pre-authorized code flow subset). */
export interface CredentialOffer {
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants: {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": string;
    };
  };
}

/** OpenID4VP Authorization Request (subset) with a DCQL query. */
export interface PresentationRequest {
  /** Verifier identifier (client_id). */
  client_id: string;
  /** Anti-replay nonce the wallet must sign in the KB-JWT. */
  nonce: string;
  /** Where the wallet posts the vp_token. */
  response_uri: string;
  response_type: "vp_token";
  response_mode: "direct_post";
  /** Digital Credentials Query Language request. */
  dcql_query: DcqlQuery;
}

/** Minimal DCQL (Digital Credentials Query Language). */
export interface DcqlQuery {
  credentials: Array<{
    id: string;
    format: "dc+sd-jwt";
    meta: { vct_values: string[] };
    /** Claims the verifier wants disclosed. */
    claims: Array<{ path: string[] }>;
  }>;
}

export interface VerificationResult {
  valid: boolean;
  /** Only the claims the holder chose to disclose. */
  disclosedClaims: Record<string, unknown>;
  /** Always-visible, issuer-signed payload claims (e.g. `status`, `iss`, `vct`, `exp`). */
  issuerClaims: Record<string, unknown>;
  errors: string[];
  issuer?: string;
  vct?: string;
}
