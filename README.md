# bw-sanitize

A small Rust CLI for reversible sanitization of Bitwarden JSON exports.

It replaces sensitive values with stable mapping tokens so you can inspect, diff, deduplicate, or reorganize vault exports without exposing the original secrets. The same original value always maps to the same token, and the mapping file can restore the sanitized JSON later.

## Features

- Sanitizes Bitwarden JSON exports while preserving the original JSON field order.
- Keeps useful deduplication fields readable, including item names, folder names, login URIs, and card numbers.
- Replaces passwords, TOTP secrets, notes, secure-note content, custom field values, identity data, passkey strings, SSH key strings, and non-number card fields.
- Reuses an existing mapping file for stable tokens across multiple exports.
- Restores sanitized JSON back to the original values with the mapping file.

## Install

Build from source:

```bash
cargo build --release
```

The binary will be available at:

```bash
target/release/bw-sanitize
```

## Usage

Sanitize an export:

```bash
cargo run -- sanitize \
  --input bitwarden_export.json \
  --output sanitized.json \
  --map mapping.json
```

Restore a sanitized file:

```bash
cargo run -- restore \
  --input sanitized.json \
  --output restored.json \
  --map mapping.json
```

Short flags are also supported:

```bash
cargo run -- sanitize -i export.json -o sanitized.json -m mapping.json
cargo run -- restore -i sanitized.json -o restored.json -m mapping.json
```

## Security Notes

`mapping.json` contains the original sensitive values. Store it privately and do not commit it, share it, or attach it to issues.

Do not publish real Bitwarden exports, mapping files, or working sanitized outputs unless you have reviewed them carefully.

## Development

```bash
cargo fmt
cargo test
cargo clippy -- -D warnings
```

See `AGENTS.md` for contributor guidelines.
