# Contributing to Docchain

Set up your machine as described in [README.md](README.md#prerequisites).

## Commands

The `justfile` holds the project's commands. This table lists what each recipe runs, so the project
stays usable without `just`. Every recipe is listed here, and every listed recipe exists. When you
change one, change the other in the same commit.

| Recipe | Runs | When |
|---|---|---|
| `just bootstrap` | Checks for `git`, `rustup`, and `cargo`; runs `rustup toolchain install --no-self-update` for `rust-toolchain.toml`; reports `cargo-nextest` and `cargo-deny`; runs `git config --local core.hooksPath .githooks` if `.githooks/` exists | Once per clone, and after a toolchain change |
| `just fmt` | `cargo fmt --all` | Before committing |
| `just lint` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | While editing |
| `just check-fast` | `cargo fmt --all --check`, then `cargo check --workspace --all-targets`, then `cargo test --workspace --lib` | While editing |
| `just test` | `cargo nextest run --workspace --all-features --no-tests=warn`, or `cargo test --workspace --all-features --all-targets` without nextest; then `cargo test --doc --workspace --all-features` | Before committing |
| `just demo-first-slice` | Enables the non-default `test-support` feature, runs `envelope_vectors`, then the six PostgreSQL and filesystem system-test targets serially with `cargo test -p docchain-server` | To run the complete invented exchange |
| `just docs` | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps` | When public docs change; add `--open` to browse |
| `just deny` | `cargo deny check` | When dependencies change |
| `just check` | `cargo fmt --all --check`, then `just lint test docs deny` | Before proposing a change |

Running `just` with no arguments lists the recipes.

`just test` and `just check` need the PostgreSQL service described in
[README.md](README.md#run-the-demonstration), because they include the system tests.

**CI runs `just check` with `CI` set.** That adds `--locked` to every Cargo command, so a stale
`Cargo.lock` fails the build instead of being rewritten. It also turns a missing `cargo-deny` from a
visible skip into a failure.

## Changes

- Use a short-lived branch from `main`, and write commit subjects in the imperative.
- Stage explicit paths and inspect `git diff --staged` before committing.
- Never commit secrets, `.env` files, local databases, or build output.
