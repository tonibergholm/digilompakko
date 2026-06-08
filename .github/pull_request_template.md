<!-- One concern per PR. See CONTRIBUTING.md and CLAUDE.md. -->

## What & why

<!-- What does this change do, and why? Link the issue: Closes #___ -->

## Type

- [ ] feat
- [ ] fix
- [ ] docs
- [ ] refactor / chore / test

## Spec impact

<!-- Which spec(s)/clause(s) does this touch? ARF / HAIP / OpenID4VCI / OpenID4VP / SD-JWT VC /
     Token Status List. Cite versions where relevant. "None" is a valid answer. -->

## Checklist

- [ ] Worked on a `type/topic` branch (worktree), not committed to `main`
- [ ] `npm run build` passes with zero TypeScript errors
- [ ] `npm test` is green; added tests for new behaviour (incl. adversarial/negative cases)
- [ ] Trust-critical logic stays in `packages/core`
- [ ] Updated `docs/COMPLIANCE.md` / `docs/ROADMAP.md` if the compliance surface changed
- [ ] No real personal data, secrets, or certification claims introduced
- [ ] Commits follow Conventional Commits and are signed off (DCO, `-s`)
