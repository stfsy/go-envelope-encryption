# Security Review & Remediation Plan (`go-envelope-encryption`)

## 1. Executive Summary

This document contains the findings from the security and reliability review of `github.com/stfsy/go-envelope-encryption` alongside a step-by-step implementation plan for remediation.

### Summary of Findings (Prioritized by Severity)

| # | Severity | Finding | Location | CWE |
| :- | :--- | :--- | :--- | :--- |
| 1 | **High** | Broken `Client.Reload` Logic Causes Silent Parameter Ignore or Cryptographic Tier Downgrade | `envelope.go` (`L131-L155`, `L191-L219`, `L389-L423`) | CWE-327 / CWE-665 |
| 2 | **Medium** | Post-Encryption Size Check and Unbounded Byte APIs Allow Memory, CPU, and KMS Quota Exhaustion (DoS) | `envelope.go` (`L278-L287`, `L332-L384`), `wire.go` (`L15-L17`) | CWE-400 / CWE-770 |
| 3 | **Medium** | Ignored `context.Context` in Mounted Secret Initialization and Keyset Unwrapping | `envelope.go` (`L131-L155`, `L191-L219`), `keyset/loader.go` (`L66-L104`) | CWE-400 / CWE-754 |
| 4 | **Medium** | TOCTOU Race Condition and Same-Size / Same-ModTime Missed Rotation in `startAutoReloader` | `envelope.go` (`L131-L155`, `L425-L470`) | CWE-367 |
| 5 | **Low** | Unclosed gRPC Connection Pool in `kms.NewGCPKMSEncrypter` | `kms/kms.go` (`L52-L73`) | CWE-404 |
| 6 | **Low** | Incomplete `KeyTemplate` Validation & Swallowed Error Defer Malformed DEK Templates to Runtime | `keyset/loader.go` (`L49-L58`), `envelope.go` (`L158-L175`, `L223-L241`) | CWE-20 / CWE-391 |
| 7 | **Low** | End-of-Life AWS SDK v1 (`github.com/aws/aws-sdk-go` v1) Dependency & Missing `pull_request` CI Triggers | `go.mod` (`L6`, `L19`), `kms/kms.go` (`L25-L46`), `.github/workflows/tests.yml`, `.github/workflows/lints.yml` | CWE-1104 |

---

## 2. Detailed Findings & Technical Analysis

### Finding 1 — [High] Broken `Client.Reload` Logic Causes Silent Parameter Ignore or Cryptographic Tier Downgrade
- **Location**: `envelope.go` lines `131-155`, `191-219`, `389-423`
- **Problem**:
  1. **Silent Parameter Ignore (`c.reloader != nil`)**: `NewFromMountedSecret` and `NewLocalEnvelopeFromMountedSecret` assign `c.reloader` to a closure that permanently captures the *initial* `secretPath` and `kmsKey`. When a caller later invokes `client.Reload(newSecretPath, newKMSKey)` (e.g., to switch to a rotated KMS master key or updated file path), `Reload` executes `c.reloader()` and **ignores the `secretPath` and `kmsKey` arguments** passed to `Reload`.
  2. **Silent Cryptographic Downgrade (`c.reloader == nil`)**: When a 2-tier envelope client is created via `NewLocalEnvelope` or `NewDirectKMSEnvelope`, `c.reloader` is `nil`. Calling `client.Reload(secretPath, kmsKey)` executes the `else` branch and replaces `c.primitive` with a 1-tier direct keyset AEAD (`aead.New(handle)`) rather than a 2-tier `KMSEnvelopeAEAD`. Subsequent `Encrypt` calls bypass ephemeral DEK generation and encrypt records directly with the Tier-2 KEK, while all previously encrypted 2-tier records fail to decrypt.

### Finding 2 — [Medium] Post-Encryption Size Check and Unbounded Byte APIs Allow Memory, CPU, and KMS Quota Exhaustion (DoS)
- **Location**: `envelope.go` lines `278-287`, `332-384`
- **Problem**:
  1. `Client.Encrypt` checks `len(Prefix)+base64.StdEncoding.EncodedLen(len(raw)) > MaxCiphertextLen` **after** `c.EncryptBytes(ctx, plaintext, aad...)` has already executed. An oversized plaintext triggers DEK generation, remote Cloud KMS encryption (in `NewDirectKMSEnvelope` mode), and full buffer allocation + symmetric encryption before being rejected.
  2. `Client.EncryptBytes` and `Client.DecryptBytes` do not enforce `MaxCiphertextLen` / `MaxRawCiphertextLen` bounds at all.

### Finding 3 — [Medium] Ignored `context.Context` in Mounted Secret Initialization and Keyset Unwrapping
- **Location**: `envelope.go` lines `131-155`, `191-219`; `keyset/loader.go` lines `66-104`
- **Problem**:
  1. `NewFromMountedSecret(ctx, ...)` and `NewLocalEnvelopeFromMountedSecret(ctx, ...)` accept `ctx context.Context` but never inspect `ctx.Err()` or pass `ctx` downstream.
  2. `keyset.LoadEncryptedKeyset` calls `tinkkeyset.Read(reader, masterKey)` instead of `tinkkeyset.ReadWithContext(ctx, reader, pwc, []byte{})`, ignoring caller context timeouts/cancellations when unwrapping keysets over the network via KMS.

### Finding 4 — [Medium] TOCTOU Race Condition and Same-Size / Same-ModTime Missed Rotation in `startAutoReloader`
- **Location**: `envelope.go` lines `131-155`, `425-470`
- **Problem**:
  1. **Startup TOCTOU Race**: `NewFromMountedSecret` and `NewLocalEnvelopeFromMountedSecret` read `secretPath` first (`loadFn()`), and only afterward does `startAutoReloader` call `os.Stat(path)` to record the initial `lastModTime` and `lastSize`. If the secret rotates on disk between `loadFn()` and `os.Stat(path)`, `startAutoReloader` records the *new* file's metadata while `Client` retains the *old* keyset in memory, missing the rotation.
  2. **Same-Size / Coarse-Timestamp Blind Spot**: `startAutoReloader` only reloads if `!fi.ModTime().Equal(lastModTime) || fi.Size() != lastSize`. A Tink keyset JSON with the same number and type of keys has a constant byte size (e.g., `554` bytes for a single AES256-GCM key). If a secret is updated within the same filesystem timestamp tick or mounted with fixed timestamps, the rotation is missed.
  3. **Uncancelable Retry Sleep**: Line 447 uses `time.Sleep(50 * time.Millisecond)` instead of a `select` on `c.stopReloader`.

### Finding 5 — [Low] Unclosed gRPC Connection Pool in `kms.NewGCPKMSEncrypter`
- **Location**: `kms/kms.go` lines `52-73`
- **Problem**:
  `gcpkms.NewClient` initializes a gRPC `kms.KeyManagementClient` connection pool. If `client.GetAEAD(uri)` fails, `client.Close()` is not called. Even on success, `client` is discarded and only `tink.AEAD` is returned, preventing callers from closing the underlying gRPC client.

### Finding 6 — [Low] Incomplete `KeyTemplate` Validation & Swallowed Error Defer Malformed DEK Templates to Runtime
- **Location**: `keyset/loader.go` lines `49-58`; `envelope.go` lines `158-175`, `223-241`
- **Problem**:
  1. `keyset.ValidateAEADTemplate` only checks `supportedAEADTypes[template.GetTypeUrl()]` (and returns `nil` for `template == nil`) without validating `template.Value` via `registry.NewKeyData(template)`. Passing a `KeyTemplate` with a valid `TypeUrl` but empty/corrupted `Value` succeeds at client initialization and fails on every `Encrypt` call at runtime.
  2. `buildLocalEnvelopeAEAD` and `NewDirectKMSEnvelope` ignore errors returned by `aead.NewKMSEnvelopeAEADWithContext` and fall back to `aead.NewKMSEnvelopeAEAD2`.

### Finding 7 — [Low] End-of-Life AWS SDK v1 Dependency & Missing `pull_request` CI Triggers
- **Location**: `go.mod` lines `6`, `19`; `kms/kms.go` lines `25-46`; `.github/workflows/tests.yml`; `.github/workflows/lints.yml`
- **Problem**:
  1. `github.com/tink-crypto/tink-go-awskms/v2` pulls in `github.com/aws/aws-sdk-go` v1, which reached AWS End-of-Support on July 31, 2025, and its `AWSAEAD` type does not implement `tink.AEADWithContext`.
  2. `.github/workflows/tests.yml` and `.github/workflows/lints.yml` only trigger on `push:` and omit `pull_request:`.

---

## 3. Step-by-Step Implementation Plan

### Step 1: Migrate `kms` Package to AWS SDK for Go v2 & Add GCP `io.Closer` Support

#### 1.1 Update `go.mod`
Remove `github.com/tink-crypto/tink-go-awskms/v2` and add AWS SDK for Go v2 packages:
```bash
go get github.com/aws/aws-sdk-go-v2@latest \
       github.com/aws/aws-sdk-go-v2/config@latest \
       github.com/aws/aws-sdk-go-v2/service/kms@latest
go mod tidy
```

#### 1.2 Modify `kms/kms.go`
- Replace `tink-go-awskms/v2` with a native AWS SDK v2 implementation (`awsAEAD`) that implements both `tink.AEAD` and `tink.AEADWithContext` while preserving 100% Tink cross-language wire compatibility:
  - Strip `"aws-kms://"` prefix from the ARN for the `KeyId` field.
  - Extract the AWS region from the ARN (`aws-kms://arn:<partition>:kms:<region>:...`).
  - When `len(associatedData) > 0`, set `EncryptionContext: map[string]string{"associatedData": hex.EncodeToString(associatedData)}` (matching Tink's `AssociatedData` context key and hex encoding).
  - Support functional options (`WithAWSConfigOptions`, `WithAWSKMSClient`) for custom credentials, endpoints, and unit test mocking.
- In `NewGCPKMSEncrypter`:
  - Call `_ = client.Close()` if `client.GetAEAD(uri)` fails.
  - Return a `gcpClosableAEAD` struct that implements `tink.AEAD`, `tink.AEADWithContext`, and `io.Closer` (`Close() error`).

```go
// kms/kms.go
package kms

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/testing/fakekms"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var (
	// ErrInvalidURI is returned when a KMS Key URI is malformed or unsupported.
	ErrInvalidURI = errors.New("kms: invalid or unsupported key URI")
	// ErrKMSInitialization is returned when a KMS client fails to initialize.
	ErrKMSInitialization = errors.New("kms: failed to initialize KMS client")

	awsARNRegionRe = regexp.MustCompile(`^aws-kms://arn:aws[a-zA-Z0-9-_]*:kms:([a-z0-9-]+):`)
)

// AWSKMSClient defines the AWS KMS API operations required for envelope encryption.
type AWSKMSClient interface {
	Encrypt(ctx context.Context, params *awskms.EncryptInput, optFns ...func(*awskms.Options)) (*awskms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *awskms.DecryptInput, optFns ...func(*awskms.Options)) (*awskms.DecryptOutput, error)
}

type awsOptions struct {
	cfgOpts []func(*config.LoadOptions) error
	client  AWSKMSClient
}

// AWSOption configures the AWS KMS encrypter.
type AWSOption func(*awsOptions)

// WithAWSConfigOptions appends custom AWS SDK v2 config load options.
func WithAWSConfigOptions(opts ...func(*config.LoadOptions) error) AWSOption {
	return func(o *awsOptions) {
		o.cfgOpts = append(o.cfgOpts, opts...)
	}
}

// WithAWSKMSClient injects a pre-configured AWS KMS client (or mock).
func WithAWSKMSClient(client AWSKMSClient) AWSOption {
	return func(o *awsOptions) {
		o.client = client
	}
}

// NewAWSKMSEncrypter initializes a tink.AEAD (and tink.AEADWithContext) primitive using AWS SDK for Go v2.
// keyARN must be a valid AWS KMS key ARN (e.g., "aws-kms://arn:aws:kms:us-east-1:123456789012:key/...")
// or standard ARN starting with "arn:aws:kms:".
func NewAWSKMSEncrypter(ctx context.Context, keyARN string, opts ...AWSOption) (tink.AEAD, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if keyARN == "" {
		return nil, fmt.Errorf("%w: key ARN cannot be empty", ErrInvalidURI)
	}

	uri := keyARN
	if !strings.HasPrefix(strings.ToLower(uri), "aws-kms://") {
		uri = "aws-kms://" + keyARN
	}

	matches := awsARNRegionRe.FindStringSubmatch(uri)
	if len(matches) != 2 {
		return nil, fmt.Errorf("%w: could not extract AWS region from ARN %q", ErrInvalidURI, keyARN)
	}
	region := matches[1]

	var o awsOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	client := o.client
	if client == nil {
		loadOpts := append([]func(*config.LoadOptions) error{config.WithRegion(region)}, o.cfgOpts...)
		cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKMSInitialization, err)
		}
		client = awskms.NewFromConfig(cfg)
	}

	rawARN := uri[len("aws-kms://"):]
	return &awsAEAD{
		keyID:  rawARN,
		client: client,
	}, nil
}

type awsAEAD struct {
	keyID  string
	client AWSKMSClient
}

var (
	_ tink.AEAD            = (*awsAEAD)(nil)
	_ tink.AEADWithContext = (*awsAEAD)(nil)
)

func (a *awsAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return a.EncryptWithContext(context.Background(), plaintext, associatedData)
}

func (a *awsAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return a.DecryptWithContext(context.Background(), ciphertext, associatedData)
}

func (a *awsAEAD) EncryptWithContext(ctx context.Context, plaintext, associatedData []byte) ([]byte, error) {
	req := &awskms.EncryptInput{
		KeyId:     aws.String(a.keyID),
		Plaintext: plaintext,
	}
	if len(associatedData) > 0 {
		req.EncryptionContext = map[string]string{
			"associatedData": hex.EncodeToString(associatedData),
		}
	}
	resp, err := a.client.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.CiphertextBlob, nil
}

func (a *awsAEAD) DecryptWithContext(ctx context.Context, ciphertext, associatedData []byte) ([]byte, error) {
	req := &awskms.DecryptInput{
		KeyId:          aws.String(a.keyID),
		CiphertextBlob: ciphertext,
	}
	if len(associatedData) > 0 {
		req.EncryptionContext = map[string]string{
			"associatedData": hex.EncodeToString(associatedData),
		}
	}
	resp, err := a.client.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

type gcpClosableAEAD struct {
	tink.AEAD
	client *gcpkms.Client
}

func (g *gcpClosableAEAD) EncryptWithContext(ctx context.Context, plaintext, associatedData []byte) ([]byte, error) {
	if pwc, ok := g.AEAD.(tink.AEADWithContext); ok {
		return pwc.EncryptWithContext(ctx, plaintext, associatedData)
	}
	return g.AEAD.Encrypt(plaintext, associatedData)
}

func (g *gcpClosableAEAD) DecryptWithContext(ctx context.Context, ciphertext, associatedData []byte) ([]byte, error) {
	if pwc, ok := g.AEAD.(tink.AEADWithContext); ok {
		return pwc.DecryptWithContext(ctx, ciphertext, associatedData)
	}
	return g.AEAD.Decrypt(ciphertext, associatedData)
}

func (g *gcpClosableAEAD) Close() error {
	if g.client != nil {
		return g.client.Close()
	}
	return nil
}
```

---

### Step 2: Harden `keyset/loader.go`

#### 2.1 Modify `keyset/loader.go`
1. In `ValidateAEADTemplate(template *tinkpb.KeyTemplate) error`:
   - Reject `template == nil` with `ErrUnsupportedKeyType`.
   - Call `registry.NewKeyData(template)` (from `github.com/tink-crypto/tink-go/v2/core/registry`) after checking `supportedAEADTypes[template.GetTypeUrl()]` so templates with empty or invalid protobuf `Value` fields are rejected immediately.
2. Add `LoadEncryptedKeysetWithContext(ctx context.Context, r io.Reader, masterKey tink.AEAD) (*tinkkeyset.Handle, error)` and `LoadMountedSecretWithContext(ctx context.Context, path string, masterKey tink.AEAD) (*tinkkeyset.Handle, error)`:
   - Check `if err := ctx.Err(); err != nil { return nil, err }`.
   - If `pwc, ok := masterKey.(tink.AEADWithContext); ok`, call `tinkkeyset.ReadWithContext(ctx, reader, pwc, []byte{})`.
   - Preserve context cancellation errors (`context.Canceled` / `context.DeadlineExceeded`) unwrapped so callers can check `errors.Is(err, context.Canceled)`.

---

### Step 3: Harden `wire.go` and `envelope.go`

#### 3.1 Modify `wire.go`
Add `MaxRawCiphertextLen`:
```go
const (
	// Prefix is the magic header identifying Tink envelope ciphertext strings.
	Prefix = "$tink$"
	// MaxCiphertextLen is the maximum allowable serialized envelope string length (32 MiB).
	MaxCiphertextLen = 32 * 1024 * 1024
	// MaxRawCiphertextLen is the maximum raw binary envelope length that fits within MaxCiphertextLen.
	MaxRawCiphertextLen = (MaxCiphertextLen - len(Prefix)) / 4 * 3
)
```

#### 3.2 Modify `envelope.go`
1. **Add `ErrReloadUnsupported`**:
   ```go
   ErrReloadUnsupported = errors.New("envelope: client does not support keyset reload")
   ```
2. **Enforce Pre-Encryption & Raw Byte Size Limits**:
   - In `Encrypt` and `EncryptBytes`, check `if len(plaintext) > MaxRawCiphertextLen { return ..., ErrCiphertextTooLarge }` **before** invoking `p.Encrypt` / `pwc.EncryptWithContext`.
   - In `DecryptBytes`, check `if len(ciphertext) > MaxRawCiphertextLen { return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, ErrCiphertextTooLarge) }` before invoking `p.Decrypt` / `pwc.DecryptWithContext`.
3. **Propagate `NewKMSEnvelopeAEADWithContext` Errors**:
   - In `buildLocalEnvelopeAEAD` and `NewDirectKMSEnvelope`, if `aead.NewKMSEnvelopeAEADWithContext(dekTemplate, pwc)` returns a non-nil `err`, return `nil, err` directly instead of falling back to `aead.NewKMSEnvelopeAEAD2`.
4. **Fix `Client.Reload` and Constructor Reloaders**:
   - Update `reloader` field type on `Client` and `options` to `func(secretPath string, kmsKey tink.AEAD) (tink.AEAD, error)`.
   - In `NewFromMountedSecret` and `NewLocalEnvelopeFromMountedSecret`:
     - Check `if err := ctx.Err(); err != nil { return nil, err }`.
     - Use `keyset.LoadMountedSecretWithContext(ctx, currentPath, currentKey)` for the initial load.
     - In the `reloader` closure, if the caller passes a non-empty `secretPath` or non-nil `kmsKey` to `Reload(secretPath, kmsKey)`, use those new values (and update the tracked defaults for subsequent auto-reloads); otherwise fall back to the configured `secretPath` and `kmsKey`.
   - In `NewLocalEnvelope`:
     - Configure a `reloader` that loads a mounted keyset from `(secretPath, kmsKey)` and wraps it with `buildLocalEnvelopeAEAD(kekAEAD, dekTemplate)` so `Reload` preserves 2-tier `KMSEnvelopeAEAD` encryption.
   - In `NewDirectKMSEnvelope`:
     - Configure a `reloader` that returns `nil, ErrReloadUnsupported` so calling `Reload` on a direct KMS client returns a clear error instead of downgrading to a 1-tier keyset AEAD.
5. **Fix `startAutoReloader` TOCTOU Race & Same-Size Rotation Detection**:
   - Compute the file's SHA-256 digest (`[32]byte`), `ModTime`, and `Size` when loading the secret file at initialization, passing the initial state into `startAutoReloader`.
   - On each tick in `startAutoReloader`:
     - Use `select { case <-c.stopReloader: return; case <-time.After(50 * time.Millisecond): }` instead of `time.Sleep(50 * time.Millisecond)` on transient `os.Stat` errors during symlink swaps.
     - Read the bounded file and compute its `sha256.Sum256` digest; if `!fi.ModTime().Equal(lastModTime) || fi.Size() != lastSize || digest != lastDigest`, call `c.Reload(path, kmsKey)` and update `lastModTime`, `lastSize`, and `lastDigest` upon success.

---

### Step 4: Add `pull_request` Triggers to CI Workflows

#### 4.1 Modify `.github/workflows/tests.yml` and `.github/workflows/lints.yml`
Update the `on:` trigger block (leaving all action version tags untouched):
```yaml
on:
  push:
  pull_request:
```

---

### Step 5: Expand Unit & Fuzz Test Suite

1. **`kms/kms_test.go`**:
   - Test `NewAWSKMSEncrypter` with a mock `AWSKMSClient` verifying `EncryptWithContext`, `DecryptWithContext`, hex-encoded `"associatedData"` in `EncryptionContext`, and `ctx` cancellation.
   - Test `NewGCPKMSEncrypter` URI validation and `io.Closer` compliance.
2. **`keyset/loader_test.go`**:
   - Test `ValidateAEADTemplate` rejecting `nil` and rejecting a `KeyTemplate` with a valid `TypeUrl` (`AesGcmKey`) but invalid/empty `Value`.
   - Test `LoadEncryptedKeysetWithContext` and `LoadMountedSecretWithContext` with a canceled `context.Context`.
3. **`envelope_test.go`**:
   - Test `Client.Reload` with updated `secretPath` and `kmsKey` arguments on `NewFromMountedSecret` and `NewLocalEnvelopeFromMountedSecret`.
   - Test `Client.Reload` on `NewLocalEnvelope` verifying that post-reload ciphertexts still use 2-tier `KMSEnvelopeAEAD` and can decrypt pre-reload ciphertexts.
   - Test `Client.Reload` on `NewDirectKMSEnvelope` returning `ErrReloadUnsupported`.
   - Test `EncryptBytes` and `DecryptBytes` rejecting payloads larger than `MaxRawCiphertextLen` with `ErrCiphertextTooLarge`, and verify `Encrypt` rejects oversized plaintext without invoking the underlying KMS AEAD.
   - Test `WithAutoReload` detecting a keyset rotation even when the rotated file has the **exact same byte size and identical `ModTime`** (via `os.Chtimes`).
   - Add `FuzzEnvelopeDecrypt(f *testing.F)` fuzzing `client.DecryptWireBytes`.

---

## 4. Verification Runbook

Run the following commands to verify the implementation:

```powershell
# 1. Verify module graph (confirm github.com/aws/aws-sdk-go v1 is gone)
go mod tidy
go list -m all

# 2. Run all unit tests with the race detector and coverage enabled
go test -race -cover -v ./...

# 3. Run fuzz targets
go test -fuzz=FuzzWire -fuzztime=10s .
go test -fuzz=FuzzEnvelopeDecrypt -fuzztime=10s .

# 4. Run benchmarks to verify hot-path performance
go test -bench=. -benchmem ./...
```
