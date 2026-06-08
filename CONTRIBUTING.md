# Contributing to Digilompakko

Thanks for your interest! This project aims to be a clean, spec-faithful EUDI wallet reference.
Contributions of code, tests, docs, and spec-conformance fixes are all welcome.

## Ground rules

- Be respectful — see [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- Read [`CLAUDE.md`](CLAUDE.md) — it documents the architecture, conventions, and the
  **worktree + PR workflow** that all changes must follow.
- This is a **reference implementation, not a certified product.** Don't introduce real personal
  data, secrets, or claims of certification.

## Workflow

1. **Find or open an issue** describing the change. For security issues, follow
   [`SECURITY.md`](SECURITY.md) instead of opening a public issue.
2. **Work in a worktree on a dedicated branch** — never commit to `main`. Worktrees live in
   `.worktrees/` (gitignored) inside the repo:
   ```bash
   git worktree add .worktrees/my-change -b feat/my-change
   cd .worktrees/my-change
   npm install
   ```
   When the PR is merged, clean up with `git worktree remove .worktrees/my-change`.
3. Make the change. Keep trust-critical logic in `packages/core`.
4. **Verify locally:**
   ```bash
   npm run build   # zero TS errors
   npm test        # all green; add tests for new behaviour
   npm run demo    # end-to-end still works
   ```
5. **Commit** using [Conventional Commits](https://www.conventionalcommits.org)
   (`feat(core): …`, `fix(verifier): …`, `docs: …`).
6. **Push and open a PR into `main`.** Fill in the PR template, link the issue, ensure CI is green.
7. Address review feedback. Squash-merge once approved.

## What makes a good PR

- One concern per PR; no unrelated refactors or formatting churn.
- New protocol code cites the relevant spec clause in comments and uses exact field names.
- Security-relevant changes include **adversarial tests** (prove the negative case).
- Docs updated (`docs/COMPLIANCE.md`, `docs/ROADMAP.md`) when the compliance surface changes.

## Good first issues

See the roadmap in [`docs/ROADMAP.md`](docs/ROADMAP.md). Approachable starting points:
self-contained `packages/core` additions with clear spec references and tests.

## Developer Certificate of Origin

By contributing you certify the [DCO](https://developercertificate.org/): you wrote the code or
have the right to submit it under the project's Apache-2.0 license. Sign off commits with `-s`.
