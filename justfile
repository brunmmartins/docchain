# Commands for building and checking Docchain.
#
# Every recipe here is listed in CONTRIBUTING.md with the commands it runs, and every `just <recipe>`
# named in this repository's documentation exists here. Change both in the same commit.
#
# CI runs these same recipes with CI set, which adds --locked.

set shell := ["bash", "-euo", "pipefail", "-c"]

# The application container installs Rust beneath CARGO_HOME without adding it to PATH.
cargo_home := env("CARGO_HOME", "/usr/local/cargo")
export PATH := cargo_home + "/bin:" + env("PATH")

locked := if env("CI", "") != "" { "--locked" } else { "" }

[private]
default:
    @{{just_executable()}} --list --unsorted

# Verify required tools, install the pinned toolchain, report optional tools and their fallbacks
bootstrap:
    #!/usr/bin/env bash
    set -euo pipefail
    for tool in git rustup cargo; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "MISSING  $tool (required; see README.md)" >&2
            exit 1
        fi
        echo "ok       $tool"
    done
    # Installs what rust-toolchain.toml names; never updates the contributor's rustup itself.
    rustup toolchain install --no-self-update
    report() {
        if cargo "$1" --version >/dev/null 2>&1; then echo "ok       cargo-$1"; else echo "absent   cargo-$1 (fallback: $2)"; fi
    }
    report nextest "cargo test"
    report deny "review new dependencies by hand; required in CI"
    if [ -d .githooks ]; then
        git config --local core.hooksPath .githooks
        echo "ok       git hooks enabled from .githooks"
    fi

# Apply formatting
fmt:
    cargo fmt --all

# Clippy on every target and feature, with warnings denied on the command line
lint:
    cargo clippy {{locked}} --workspace --all-targets --all-features -- -D warnings

# Seconds-scale gate: formatting, compilation, library unit tests
check-fast:
    cargo fmt --all --check
    cargo check {{locked}} --workspace --all-targets
    cargo test {{locked}} --workspace --lib

# All tests: nextest if installed, else cargo test; doc tests always run separately
test:
    #!/usr/bin/env bash
    set -euo pipefail
    if cargo nextest --version >/dev/null 2>&1; then
        cargo nextest run {{locked}} --workspace --all-features --no-tests=warn
    else
        echo "cargo-nextest not installed: using cargo test" >&2
        cargo test {{locked}} --workspace --all-features --all-targets
    fi
    cargo test {{locked}} --doc --workspace --all-features

# Prove the complete invented first exchange against isolated PostgreSQL schemas and filesystem roots
demo-first-slice:
    cargo test {{locked}} -p docchain-server --features test-support --test envelope_vectors
    cargo test {{locked}} -p docchain-server --features test-support --test send_copy --test acceptance --test replay \
        --test schema_rejection --test privacy --test integrity -- --test-threads=1

# Build API documentation; broken intra-doc links fail
docs:
    RUSTDOCFLAGS="-D warnings" cargo doc {{locked}} --workspace --all-features --no-deps

# Advisories, licences, bans, and sources; skips visibly locally, fails in CI without cargo-deny
deny:
    #!/usr/bin/env bash
    set -euo pipefail
    if cargo deny --version >/dev/null 2>&1; then
        cargo deny {{locked}} check
    elif [ -n "${CI:-}" ]; then
        echo "cargo-deny is required in CI" >&2
        exit 1
    else
        echo "SKIPPED  deny: cargo-deny is not installed; review new dependencies by hand (CONTRIBUTING.md)" >&2
    fi

# Full pre-push gate, identical to CI: formatting, lint, test, docs, deny
check:
    cargo fmt --all --check
    {{just_executable()}} lint test docs deny
