# AGENTS.md — go-envelope-encryption

Tactical instructions and operational guidelines for AI coding agents (Codex, Claude Code, Cursor, Devin, Aider, Antigravity) working in `go-envelope-encryption`.

## Overview & Architecture

`go-envelope-encryption` (`github.com/stfsy/go-envelope-encryption`) is a production-grade Go library providing high-throughput, low-latency envelope encryption powered by Google Tink (`tink-go/v2`). It is purpose-built for cloud container runtimes (Cloud Run, AWS ECS/Fargate, Kubernetes) and distributed databases.

### 3-Tier Key Hierarchy
1. **Tier 1 (Root KEK — Cloud KMS)**: Remote KMS (AWS KMS or GCP Cloud KMS). Invoked **only once at container startup** to unseal the application keyset.
2. **Tier 2 (Application Master Keyset)**: KMS-encrypted keyset JSON mounted into the container or loaded from disk. Unsealed into memory as a Tink `KeysetHandle`. Supports hot-reloading (`WithAutoReload`) and dual-read rotation.
3. **Tier 3 (Per-Record Ephemeral DEK)**: In-memory Google Tink `KMSEnvelopeAEAD2`. Generates a fresh ephemeral Data Encryption Key (DEK) per record (~2.0µs hot path, zero runtime Cloud KMS network calls).

### Package Layout
- `.` (Root package):
  - [envelope.go](file:///d:/go-envelope-encryption/envelope.go): Core client (`envelope.Client`), constructors (`NewLocalEnvelope`, `NewDirectKMSEnvelope`, `NewLocalEnvelopeFromMountedSecret`, `NewFromMountedSecret`), options (`WithAutoReload`, `WithReloadErrorCallback`), crypto APIs (`Encrypt`, `Decrypt`, `EncryptBytes`, `DecryptBytes`, `DecryptWireBytes`), and key rotation/reloader logic.
  - [wire.go](file:///d:/go-envelope-encryption/wire.go): `$tink$` prefix envelope wire formatting, validation, and Base64 encoding/decoding.
  - [bench_test.go](file:///d:/go-envelope-encryption/bench_test.go): In-memory crypto and wire parsing benchmarks.
- [keyset/](file:///d:/go-envelope-encryption/keyset): Encrypted keyset lifecycle management ([keyset/loader.go](file:///d:/go-envelope-encryption/keyset/loader.go)): generation, loading, path unsealing, template validation, and rotation.
- [kms/](file:///d:/go-envelope-encryption/kms): Cloud KMS integrations ([kms/kms.go](file:///d:/go-envelope-encryption/kms/kms.go)): AWS KMS (`aws-kms://`), GCP Cloud KMS (`gcp-kms://`), and `FakeKMS` / `MockKMSEncrypter` for testing.
- [scripts/](file:///d:/go-envelope-encryption/scripts): SecOps administrative Python CLI utilities (`create_keyset.py`, `rotate_keyset.py`) for CI/CD secret provisioning.

---

## Setup & Dependency Commands

- **Fetch Go dependencies**:
  ```bash
  go mod download
  ```
- **Verify Go module integrity**:
  ```bash
  go mod verify
  ```
- **Tidy Go dependencies** (only when modifying `go.mod` imports):
  ```bash
  go mod tidy
  ```
- **Python helper environment** (only when maintaining scripts in `scripts/`):
  ```bash
  python -m venv scripts/.env
  scripts/.env/Scripts/pip install tink boto3 google-cloud-kms   # Windows PowerShell
  # source scripts/.env/bin/activate && pip install tink boto3 google-cloud-kms  # Linux/macOS
  ```

---

## Verification & Testing Mandate ("Smallest Sensible Subset")

Always execute scoped, package-level tests matching the files touched. Never run repository-wide test sweeps when modifying isolated packages.

### Targeted Test Matrix

| Changed Path | Primary Test Command | Secondary / Edge Checks |
| :--- | :--- | :--- |
| `envelope.go`, `wire.go` (Root package) | `go test -v .` | `go test -race -v .` |
| `wire.go` (Wire serialization changes) | `go test -v -run TestWire .` | `go test -run=^$ -fuzz=FuzzWire -fuzztime=5s .` |
| Hot crypto path / Allocations | `go test -v -run TestLocalEnvelope .` | `go test -bench . -benchmem .` |
| Keyset loading / rotation (`keyset/*`) | `go test -v ./keyset/...` | `go test -race -v ./keyset/...` |
| KMS adapters (`kms/*`) | `go test -v ./kms/...` | `go test -race -v ./kms/...` |
| Python SecOps scripts (`scripts/*`) | `python scripts/create_keyset.py --help` | `python scripts/rotate_keyset.py --help` |
| Cross-package refactoring / `go.mod` | `go test -race -v ./...` | `go vet ./...` |

### Boundaries & Rules
- **Do NOT run** full repo benchmarks (`go test -bench .`) during simple bug fixes or doc changes.
- **Do NOT run** Go tests when only editing `scripts/*.py` or markdown documentation.
- **Do NOT run** long-running fuzz tests (`fuzztime > 30s`) in automated agent loops; keep sanity fuzz runs to `5s`–`10s`.
- **Do NOT invoke** external cloud KMS APIs during tests. Always rely on `kms.NewMockKMSEncrypter("")` or `kms.FakeKMS`.

---

## Build, Test, and Lint Commands

### Testing
- **Run all tests (local sanity)**:
  ```bash
  go test -cover -race -v ./...
  ```
- **Run benchmarks**:
  ```bash
  go test -bench . -benchmem
  ```
- **Run specific benchmark**:
  ```bash
  go test -bench=BenchmarkEncrypt$ -benchmem .
  ```
- **Run fuzz tests**:
  ```bash
  go test -run=^$ -fuzz=FuzzEnvelopeDecrypt -fuzztime=10s .
  go test -run=^$ -fuzz=FuzzWire -fuzztime=10s .
  ```

### Linting & Static Analysis
- **Standard Go Vet**:
  ```bash
  go vet ./...
  ```
- **Local golangci-lint** (if installed):
  ```bash
  golangci-lint run ./...
  ```
- **Containerized Linter** (mirrors CI workflow `.github/workflows/lints.yml`):
  ```bash
  # Linux / macOS / Git Bash
  ./lint.sh

  # Windows PowerShell
  docker run --rm -v "${PWD}:/app" -w /app golangci/golangci-lint:latest golangci-lint run -v
  ```

---

## Code Style & Implementation Conventions

### Go Idioms & Quality
- **Formatting**: Format code with standard `gofmt -s -w <file>` and manage imports with `goimports`.
- **Error Handling**:
  - Always separate error declaration from condition check:
    ```go
    // Correct:
    result, err := someOperation()
    if err != nil {
        return nil, fmt.Errorf("envelope: failed operation: %w", err)
    }

    // Prohibited:
    if err := someOperation(); err != nil { ... }
    ```
  - Wrap errors with clear context using `fmt.Errorf("envelope: ...: %w", err)`.
  - Preserve standard sentinel errors declared in [envelope.go](file:///d:/go-envelope-encryption/envelope.go) (`ErrNilPrimitive`, `ErrNilPlaintext`, `ErrDecryptionFailed`, `ErrClientClosed`, `ErrInvalidAAD`, `ErrNilContext`, `ErrReloadUnsupported`).
- **Context Management**:
  - Accept `ctx context.Context` as the first argument in all exported I/O and cryptographic operations.
  - Check context cancellation early via `checkCtx(ctx)`.
  - Propagate parent contexts down to KMS and Tink calls. Never instantiate `context.Background()` or `context.TODO()` inside core package methods (only in test harnesses).
- **Zero-Allocation & Performance Awareness**:
  - Pay attention to memory allocations on hot encryption paths (`Encrypt`, `Decrypt`, `EncryptBytes`, `DecryptBytes`).
  - Pre-allocate byte slices with appropriate capacities where bounds are known.
  - Enforce payload size limits (`MaxCiphertextLen`, `MaxRawCiphertextLen`) prior to heavy cryptographic processing to prevent DoS.
- **Wire Format Contract**:
  - Ciphertexts must adhere to `$tink$<standard_base64_payload>`.
  - Binary APIs (`EncryptBytes`, `DecryptBytes`) operate on raw byte envelopes.
  - Wire APIs (`Encrypt`, `Decrypt`, `DecryptWireBytes`, `FormatWire`, `ParseWire`) manage the `$tink$` prefix and Base64 wrapping.

### Concurrency & Thread-Safety
- `Client` must remain safe for concurrent use by multiple goroutines.
- Protect mutable state (`c.primitive`, `c.closed`) using atomic pointers (`atomic.Pointer[tink.AEAD]`, `atomic.Bool`) or `sync.RWMutex`.
- Ensure background goroutines spawned by `WithAutoReload` terminate cleanly when `Client.Close()` is called via stop channels (`c.stopReloader`).

---

## PR & Commit Guidelines

- **Commit Message Format**: Follow [Conventional Commits](https://www.conventionalcommits.org/):
  ```
  <type>[optional scope]: <description in imperative mood>

  [optional body explaining why and what]

  [optional footer: Closes #issue]
  ```
- **Allowed Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`.
- **Pre-PR Verification**:
  1. Targeted package tests pass with race detector: `go test -race ./...`
  2. Static checks pass: `go vet ./...`
  3. Code formatted: `gofmt -s -w .`
