/**
 * Structured error model.
 *
 * Codes follow the OpenID4VCI/OpenID4VP and OAuth 2.0 error registries where applicable,
 * plus a few wallet-internal codes. Carrying a stable `code` lets services return
 * spec-shaped error responses ({ error, error_description }) and lets callers branch
 * on failures without string matching.
 */
export type ErrorCode =
  // OAuth 2.0 / OpenID4VCI token + credential endpoints
  | "invalid_request"
  | "invalid_grant"
  | "invalid_token"
  | "invalid_proof"
  | "unsupported_credential_format"
  // OpenID4VP presentation
  | "invalid_presentation"
  | "access_denied"
  // Wallet / verifier internal
  | "untrusted_issuer"
  | "credential_revoked"
  | "credential_expired"
  | "holder_binding_failed"
  | "status_unavailable";

export class Oid4vcError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  constructor(code: ErrorCode, description: string, httpStatus = 400) {
    super(description);
    this.name = "Oid4vcError";
    this.code = code;
    this.status = httpStatus;
  }
  /** Spec-shaped JSON body for HTTP responses. */
  toJSON() {
    return { error: this.code, error_description: this.message };
  }
}

/**
 * Express helper: send an Oid4vcError (or unknown error) as a spec-shaped response.
 *
 * LOW-1 fix: unexpected errors are logged to stderr but NOT echoed to the client.
 * Raw exception messages can leak stack frames, internal paths, or dependency versions.
 * Only Oid4vcError instances (with controlled, spec-registry codes) reach the response body.
 */
export function sendError(res: { status: (n: number) => { json: (b: unknown) => void } }, e: unknown): void {
  if (e instanceof Oid4vcError) {
    res.status(e.status).json(e.toJSON());
  } else {
    // Log the real cause server-side; return a generic message to the client.
    console.error("[server_error]", e);
    res.status(500).json({ error: "server_error", error_description: "an internal error occurred" });
  }
}
