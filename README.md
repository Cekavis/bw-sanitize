# bw-sanitize

A small Rust CLI for reversible sanitization of Bitwarden JSON exports.

It replaces sensitive values with stable mapping tokens so you can inspect, diff, deduplicate, or reorganize vault exports without exposing the original secrets. The same original value always maps to the same token, and the mapping file can restore the sanitized JSON later.

## Features

- Sanitizes Bitwarden JSON exports while preserving the original JSON field order.
- Keeps useful deduplication fields readable, including item names, folder names, login URIs, and card numbers.
- Replaces passwords, TOTP secrets, notes, secure-note content, custom field values, identity data, passkey strings, SSH key strings, and non-number card fields.
- Reuses an existing mapping file for stable tokens across multiple exports.
- Restores sanitized JSON back to the original values with the mapping file.
- Analyzes sanitized login items for conservative merge candidates, ambiguous
  credential reuse, and same-account same-site password conflicts.

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

Analyze a sanitized export for entries that may be merged:

```bash
cargo run -- analyze \
  --input sanitized.json \
  --output merge-report.md \
  --json merge-report.json
```

The analysis command does not modify the input export. It groups only
high-confidence matches as merge candidates, keeps ambiguous same-credential
reuse in a review-only section, and reports same-account same-site entries with
different password hashes separately. Reports use short hashes derived from
sanitized tokens instead of printing full username or password tokens.

Apply high-confidence merge candidates to a sanitized export:

```bash
cargo run -- merge \
  --input sanitized.json \
  --output merged.json \
  --manual-group 'http://192.168.31.87:5000/,http://100.104.90.58:5000/'
```

The merge command keeps the earliest item in each merged group, appends unique
URIs and other mergeable arrays to it, and removes the duplicate items. Manual
groups are only applied when the matched items share the same sanitized
username/password pair; same-site password conflicts are skipped.

## Security Notes

`mapping.json` contains the original sensitive values. Store it privately and do not commit it, share it, or attach it to issues.

Do not publish real Bitwarden exports, mapping files, or working sanitized outputs unless you have reviewed them carefully.

Analysis reports can still reveal item names, hosts, and URI relationships from
the sanitized export. Treat them as private working files.

## Development

```bash
cargo fmt
cargo test
cargo clippy -- -D warnings
```

See `AGENTS.md` for contributor guidelines.
