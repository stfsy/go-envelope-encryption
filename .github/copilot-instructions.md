# go-envelope-encryption — Copilot / AI contributor instructions

This repository implements production-grade Go envelope encryption powered by Google Tink (`tink-go/v2`). Keep this file as the single-page guide for automated coding agents and contributors.

Repository URL: `https://github.com/stfsy/go-envelope-encryption`
Go Module: `github.com/stfsy/go-envelope-encryption`

Essentials (what to know):
- Purpose: Library package exposing envelope encryption clients (`envelope.Client`) using a 3-tier key hierarchy (Root KMS KEK -> Encrypted Keyset JSON / Local KEK -> Per-Record Ephemeral DEK).
- Core root package: `envelope.go` defines `Client`, constructors (`NewLocalEnvelope`, `NewDirectKMSEnvelope`, `NewLocalEnvelopeFromMountedSecret`), options, and crypto operations (`Encrypt`, `Decrypt`, `EncryptBytes`, `DecryptBytes`).
- Wire format: `wire.go` provides standard `$tink$` prefix envelope formatting and base64 parsing.
- Subpackages:
  - `keyset`: Encrypted keyset generation, loading, and secret watcher / auto-reload helpers.
  - `kms`: Cloud KMS AEAD bindings (AWS KMS, GCP Cloud KMS, FakeKMS mock for tests).
- Administrative scripts: `scripts/create_keyset.py` and `scripts/rotate_keyset.py` for Python-based keyset provisioning and rotation in CI/CD.

Quick commands (repo root):
- Fetch deps: `go mod download`
- Run tests: `go test ./...`
- Run benchmarks: `go test -bench . -benchmem`
- Run linters: `./lint.sh`

Project-specific patterns and conventions:
- Public surface: `envelope.go`, `wire.go`, `keyset/loader.go`, `kms/kms.go`. Avoid breaking changes to public APIs.
- Error handling: Follow `.github/instructions/go.instructions.md`. Handle errors explicitly, wrap errors with context, and avoid single-line declarations.
- Context management: Accept `context.Context` on encryption/decryption methods and propagate to KMS operations when supported.
- Conventional Commits: Follow Conventional Commits format for commit messages (e.g., `feat: ...`, `fix: ...`).
