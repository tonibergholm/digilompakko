# Security Policy

## Status of this project

Digilompakko is a **reference / demonstration** implementation of an EUDI wallet. It uses
**software-held keys and in-memory state** and is **not certified or hardened for production**.
Do not use it to handle real identity data. See `docs/COMPLIANCE.md` §6 for the gap to a certified
wallet.

That said, the cryptographic and protocol logic is meant to be *correct*, and we take reports of
flaws seriously — a subtle verification bug here would mislead people learning the standards.

## Reporting a vulnerability

**Please report security issues privately. Do not open a public issue.**

- Preferred: use the repository host's private vulnerability reporting
  (GitHub Security Advisories / Codeberg private issue) if available.
- Otherwise, contact the maintainers directly (see repository metadata / `MAINTAINERS`).

Please include: affected component, version/commit, a description, and ideally a reproduction or
proof-of-concept. We aim to acknowledge within a few days and will coordinate a fix and disclosure
timeline with you.

## Scope of interest

- Verification bypasses (accepting an invalid signature, revoked/expired credential, replay,
  forged holder binding, untrusted issuer).
- Selective-disclosure leaks (claims revealed that were not disclosed).
- Status List / trust-resolution logic errors.

## Out of scope

- The documented demo limitations (software keys, no WSCD, in-memory stores, no real PID/eID).
- Denial of service against the demo services.
