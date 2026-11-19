# Contributing

The organisation-wide guide applies: see
[TogetherWeOwn/.github CONTRIBUTING.md](https://github.com/TogetherWeOwn/.github/blob/main/CONTRIBUTING.md).

In short, for this repository:

1. Work on a branch and open a pull request against `main`. Direct pushes and force pushes to `main` are
   blocked; pull requests are squash-merged.
2. The PR title is a Conventional Commits header, for example `feat(contract): add bucket usage`.
3. These checks must pass: `ci-ok` (workflow lint, dependency scan, contract build check, lint, tests,
   deny-list, Rust fmt, clippy, tests and wasm32 build), `gitleaks`, CodeQL and `pr-standards`. Every review
   thread must be resolved.
4. A contract change edits `openapi/openapi.src.yaml` or `errors/catalogue.yaml`, then runs `pnpm run build`
   and `cargo run -p xtask -- gen`, and commits the regenerated files. A new operation also needs a row in
   `registry/operations.yaml`.
5. Changes inside `/v1` are additive only. Never rename or remove an error `code`.
6. Never commit secrets, `.env` or `.dev.vars` files, or production configuration values.
