# CLAUDE.md

Guidance for AI agents (and humans) working in this repository. Read this before making changes.

## What this project is

**Digilompakko** is an open-source, spec-aligned **EUDI (European Digital Identity) wallet**
reference: an end-to-end demo of **issuer + wallet + verifier** built to the EU **Architecture &
Reference Framework (ARF) 2.x** and the **OpenID4VC High Assurance Interoperability Profile
(HAIP) 1.0**. It is intended to be a clean, well-tested foundation that could grow toward
Finland's *Suomi.fi Wallet* (digilompakko) being procured by DVV under eIDAS 2.0.

It is a **reference/learning implementation, not a certified production wallet.** See
`docs/COMPLIANCE.md` §6 for the explicit gap to certification. Do not claim certification-readiness.

## Repository map

```
packages/core   Trust-critical library — crypto (ES256/P-256), SD-JWT VC issue/verify,
                Key Binding JWT, Token Status List, trust resolver, error model. NO HTTP here.
apps/issuer     OpenID4VCI 1.0 issuer (PID provider) + Status List endpoints   (port 4001)
apps/verifier   OpenID4VP 1.0 verifier with trust + revocation checks          (port 4002)
apps/wallet     Holder wallet + minimal web UI                                  (port 4000)
scripts/demo.ts Headless end-to-end demo
docs/           COMPLIANCE.md (spec traceability) · ARCHITECTURE.md · ROADMAP.md
```

## Commands

```bash
npm install      # install workspaces
npm run build    # tsc --build across all projects (must pass with 0 errors)
npm test         # node:test suite for packages/core (must stay green)
npm run demo     # headless issue -> present -> verify
npm start        # run all three services; UI at http://localhost:4000
```

## Git workflow — non-negotiable

1. **Never commit directly to `main`.** `main` is protected and only changes via merged PRs.
2. **Always work in a git worktree on a dedicated branch**, one branch per logical change.
   Worktrees live in `.worktrees/` (gitignored) inside the repo:
   ```bash
   git worktree add .worktrees/<short-topic> -b <type>/<short-topic>
   cd .worktrees/<short-topic>
   # ...do the work, commit, push...
   git push -u origin <type>/<short-topic>
   ```
   Worktrees keep `main` clean and let parallel changes proceed without stashing. Remove a
   worktree when its PR is merged: `git worktree remove .worktrees/<short-topic>`.
3. **Branch names:** `feat/…`, `fix/…`, `docs/…`, `chore/…`, `refactor/…`, `test/…`.
4. **Commits:** [Conventional Commits](https://www.conventionalcommits.org)
   (`feat(core): add token status list`, `fix(verifier): reject revoked credentials`).
5. **Open a PR into `main`.** Fill in the PR template, link the issue, ensure CI is green and at
   least one review approves before merge. Squash-merge is preferred; keep `main` history linear.
6. **One concern per PR.** Don't mix a feature with unrelated refactors or formatting churn.

## Coding conventions

- **TypeScript, ESM, `strict` mode.** No `any` in `packages/core`; prefer precise types and
  `unknown` + narrowing at boundaries (e.g. casting `await res.json()`).
- **Never hand-roll signature cryptography.** All JWS/JWT operations go through `jose`. Hashing
  and random salts use Node `crypto`. HAIP mandates **ES256 / P-256** — do not add other suites
  without a roadmap decision and tests.
- **Keep trust-critical logic in `packages/core`** (crypto, SD-JWT VC, status list, trust). Apps
  are thin HTTP layers over it. This keeps the security surface testable and reusable.
- **Spec fidelity over cleverness.** When implementing a protocol step, cite the spec clause in a
  comment and name fields exactly as the spec does (`pre-authorized_code`, `vp_token`, `cnf`, …).
- **Errors:** throw `Oid4vcError` with a registry `code`; HTTP handlers use `sendError`.

## Testing requirements

- Any change to `packages/core` **must** keep `npm test` green and add tests for new behaviour,
  especially security properties (selective disclosure, holder binding, replay, revocation, trust).
- Adversarial tests are expected: prove the *negative* (revoked → invalid, wrong nonce → fail,
  untrusted issuer → rejected), not just the happy path.
- `npm run build` must pass with zero TypeScript errors before opening a PR.

## Security & data

- This is a demo: **software keys, in-memory state, no real eID/PID**. Do not introduce real
  personal data, secrets, or credentials into the repo or fixtures (the demo subject is fictional).
- Never weaken verification to make a demo "work" — fix the demo instead.
- Report vulnerabilities per `SECURITY.md` (privately), do not open public issues for them.

## Definition of done for a change

- [ ] Built in a worktree on a `type/topic` branch (not `main`)
- [ ] `npm run build` clean, `npm test` green, new tests added where relevant
- [ ] Spec clauses cited in comments for protocol changes
- [ ] `docs/` updated (COMPLIANCE traceability / ROADMAP) if compliance surface changed
- [ ] PR opened into `main` with the template filled and CI green
