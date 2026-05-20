# Repository Guidelines

## Project Structure & Module Organization

This repository contains a Rust CLI for reversible sanitization of Bitwarden JSON exports.

- `src/main.rs` defines the command-line interface and file I/O wiring.
- `src/lib.rs` contains the sanitizer, restore logic, JSON traversal policy, mapping model, and unit tests.
- `Cargo.toml` declares dependencies and Rust edition settings.
- `Cargo.lock` is committed for reproducible CLI builds.
- `target/` is build output and must not be committed.

Do not commit real Bitwarden exports, sanitized working files, or mapping files. The mapping file contains original sensitive values.

## Build, Test, and Development Commands

Use Cargo for all local development:

```bash
cargo build
cargo test
cargo clippy -- -D warnings
cargo fmt
```

- `cargo build` compiles the CLI.
- `cargo test` runs unit tests in `src/lib.rs`.
- `cargo clippy -- -D warnings` enforces lint cleanliness.
- `cargo fmt` applies standard Rust formatting.

Run the CLI locally:

```bash
cargo run -- sanitize -i export.json -o sanitized.json -m mapping.json
cargo run -- restore -i sanitized.json -o restored.json -m mapping.json
```

## Coding Style & Naming Conventions

Follow standard Rust style via `rustfmt`. Use 4-space indentation, `snake_case` for functions and variables, `PascalCase` for structs/enums, and clear module-level separation between CLI concerns and library behavior.

Prefer path-policy tests over broad rewrites when changing sanitization behavior. Keep JSON traversal conservative: preserve unknown structure, and mask unknown item strings unless explicitly safe.

## Testing Guidelines

Tests use Rust’s built-in test framework and live in `src/lib.rs` under `#[cfg(test)]`. Add focused tests for every policy change, especially:

- repeated values mapping to the same token,
- field preservation rules,
- card-number handling,
- sanitize-then-restore round trips,
- reuse of an existing mapping file.

Run `cargo test` and `cargo clippy -- -D warnings` before opening a PR.

## Commit & Pull Request Guidelines

Use Conventional Commits, matching existing history:

```text
feat: add reversible Bitwarden JSON sanitizer
fix: preserve card number during sanitization
test: cover restore round trip
```

Pull requests should include a short description, behavior changes, test results, and any security implications. Link related issues when available. Never attach real vault exports or mapping files to issues, PRs, or test fixtures.
