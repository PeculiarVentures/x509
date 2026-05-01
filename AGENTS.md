# Project Guidelines

## Scope

- This repository is a TypeScript library for parsing, generating, and validating X.509-related data.
- Primary source files live in `src/`.
- Tests live in `test/`; the Vitest config includes all `test/**/*.ts` files.
- `build/` contains generated artifacts from Rollup. Do not hand-edit `build/` unless the task is explicitly about generated output.
- `website/` contains the Docusaurus documentation site and is separate from most core library changes.

## Environment

- Use Node.js `>=20` and npm `>=10`.
- Work from the repository root unless a task is explicitly scoped to `website/`.

## Editing Rules

- Prefer changes in `src/` and keep them minimal and localized.
- When behavior changes, update or add the corresponding test coverage in `test/` in the same change.
- If a public API changes, make sure the export surface in `src/index.ts` stays correct.
- Follow the existing TypeScript style in the repository: strict typing, double quotes, and small focused edits.

## Test Requirements

- Every functional change in `src/` must include a relevant test update or a new test.
- Every bug fix must add a regression test that would fail before the fix.
- New parsing, formatting, certificate, CRL, CSR, or extension logic should cover both successful and invalid input paths when applicable.
- Keep tests deterministic. Avoid network access, unstable timing assumptions, and unnecessary randomness.
- While iterating, prefer the narrowest relevant test file. Before handing work off, run the full test suite.

## Commit Messages

- Write commit subjects in English.
- Use Conventional Commit style with one of these types only: `feat`, `refactor`, `fix`, `chore`, `docs`, `test`, `style`.
- Preferred format: `<type>(optional-scope): imperative summary`.
- Examples:
  - `feat(algorithm): add ML-DSA signer support`
  - `fix(crl): reject duplicate serial numbers`
  - `test(x509): add PEM regression coverage`
  - `docs(readme): clarify Reflect polyfill requirement`

## Final Verification

- After changing code, run targeted checks first, then run full-project verification before finishing.
- Recommended final verification for code changes includes linting, tests, and type checks.
- Run a full build when packaging, exports, or generated artifacts may be affected.

Example commands:

```sh
npm run lint -- .
npm test
npx tsc --noEmit
```

Useful targeted commands while iterating:

```sh
npm run lint -- src test
npx vitest run test/issues.ts
npx tsc --noEmit
```

Optional build check when relevant:

```sh
npm run build
```
