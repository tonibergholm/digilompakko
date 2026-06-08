/**
 * Relying Party (verifier) registration.
 *
 * Under the ARF, a Relying Party must be **registered** before it can request attributes, and is
 * issued access certificates declaring which attributes it is entitled to ask for. This module is
 * a lightweight in-memory registry modelling that gate: a verifier presents a registered
 * `client_id`, and a wallet can refuse requests from unregistered RPs or for attributes the RP is
 * not entitled to. Real access certificates (X.509 + Trusted List) are future work.
 */
import { Oid4vcError } from "./errors.js";

export interface RelyingParty {
  client_id: string;
  name: string;
  /** Attributes the RP is entitled to request (data-minimisation gate). */
  entitled_attributes: string[];
  redirect_uris?: string[];
}

export class RelyingPartyRegistry {
  private rps = new Map<string, RelyingParty>();

  register(rp: RelyingParty): RelyingParty {
    this.rps.set(rp.client_id, rp);
    return rp;
  }

  get(clientId: string): RelyingParty | undefined {
    return this.rps.get(clientId);
  }

  isRegistered(clientId: string): boolean {
    return this.rps.has(clientId);
  }

  /** Throw unless the RP is registered. */
  assertRegistered(clientId: string): RelyingParty {
    const rp = this.rps.get(clientId);
    if (!rp) throw new Oid4vcError("access_denied", `relying party not registered: ${clientId}`, 403);
    return rp;
  }

  /** Throw unless the RP is registered AND entitled to every requested attribute. */
  assertEntitled(clientId: string, requested: string[]): RelyingParty {
    const rp = this.assertRegistered(clientId);
    const over = requested.filter((a) => !rp.entitled_attributes.includes(a));
    if (over.length) {
      throw new Oid4vcError("access_denied", `RP ${clientId} not entitled to: ${over.join(", ")}`, 403);
    }
    return rp;
  }
}
