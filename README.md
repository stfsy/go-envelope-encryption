# go-envelope-encryption

[![Tests](https://github.com/stfsy/go-envelope-encryption/actions/workflows/tests.yml/badge.svg)](https://github.com/stfsy/go-envelope-encryption/actions/workflows/tests.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/stfsy/go-envelope-encryption)](https://goreportcard.com/report/github.com/stfsy/go-envelope-encryption)
[![Go Reference](https://pkg.go.dev/badge/github.com/stfsy/go-envelope-encryption.svg)](https://pkg.go.dev/github.com/stfsy/go-envelope-encryption)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Production-grade Go envelope encryption library powered by **Google Tink (`tink-go/v2`)**, purpose-built for cloud container runtimes (Google Cloud Run, AWS ECS/Fargate, Kubernetes) and distributed databases (MongoDB, PostgreSQL, DynamoDB).

---

## 🔒 Why This Architecture?

Traditional cloud KMS encryption calls remote APIs on every encrypt and decrypt operation. At scale, this introduces significant drawbacks:
- **Cloud Latency**: 15ms – 40ms network round-trip per record.
- **Runaway Cloud Costs**: AWS KMS charges $0.03 per 10,000 requests. High-throughput workloads (50M ops/month) run up hundreds to thousands of dollars in cloud KMS bills.
- **Throttling & Outages**: Distributed microservices can easily hit cloud KMS per-second rate limits.

`go-envelope-encryption` implements an enterprise **3-Tier Key Hierarchy**:
1. **Tier 1 (Root KEK — Cloud KMS)**: Remains safely inside your Cloud Hardware Security Module (AWS KMS / GCP Cloud KMS). It is invoked **only once at container startup** to unseal the application keyset.
2. **Tier 2 (Application Master Keyset)**: Stored as a KMS-encrypted secret mounted directly into the container (via Cloud Run Secret Mounts, AWS ECS, or K8s Secret volumes). Decrypted once into container memory at boot.
3. **Tier 3 (Per-Record Ephemeral DEK)**: Uses Google Tink's `KMSEnvelopeAEAD2` to generate a fresh, isolated Data Encryption Key (DEK) for every record. The DEK is encrypted by Tier 2 and embedded into the payload envelope.

```
+--------------------------------------------------------------------------+
| Tier 1: Cloud KMS (AWS KMS / GCP Cloud KMS)                             |
|  - Root Key Encryption Key (KEK) inside cloud HSM                        |
|  - Invoked ONCE at container startup to unseal the application keyset    |
+--------------------------------------------------------------------------+
                                    │ (Cost: $0.00003 at boot)
                                    ▼
+--------------------------------------------------------------------------+
| Tier 2: Application Master Keyset (Mounted File / Secrets Manager)       |
|  - Encrypted Keyset JSON mounted at /secrets/app-keyset.json             |
|  - Loaded into container memory as an active Tink KeysetHandle           |
|  - Supports zero-downtime rotation and multi-key dual reads              |
+--------------------------------------------------------------------------+
                                    │ (Zero KMS Network Calls on Hot Path)
                                    ▼
+--------------------------------------------------------------------------+
| Tier 3: Per-Record Ephemeral DEK (Data Path: ~2.0µs / >500k ops/sec)     |
|  - Fresh ephemeral DEK generated for each record (zero nonce reuse risk) |
|  - Envelope format: $tink$<base64_standard_envelope>                     |
+--------------------------------------------------------------------------+
```

---

## ⚡ Key Features

- **Zero KMS API Costs on Data Path**: Cloud KMS is called once at container startup. All runtime record encryptions/decryptions run 100% in local memory.
- **Per-Record Isolation**: Every document or field receives a unique ephemeral DEK, eliminating AES-GCM nonce collision risks.
- **Zero-Downtime Key Rotation**: Seamless dual-read rotation. Historical records decrypt automatically while new writes use the latest primary key.
- **Automatic Hot-Reloading**: Container clients can watch mounted secret volumes (`WithAutoReload`) to atomically reload keysets without restarting the service.
- **Tampering & AAD Protection**: Supports Additional Authenticated Data (AAD) to cryptographically bind ciphertexts to tenant IDs, document IDs, or field names.
- **Cross-Language SecOps (Python)**: Official Python administrative scripts (`scripts/create_keyset.py`, `scripts/rotate_keyset.py`) for CI/CD secret provisioning.
- **Sub-Microsecond Decryption**: ~2.0µs per operation (>500k ops/sec on modern cores).

---

## 📦 Installation

```bash
go get github.com/stfsy/go-envelope-encryption
```

---

## 🚀 Quickstarts

### Pattern 1: Cloud Run / AWS ECS Secret Mount (Recommended)

Mount your KMS-encrypted keyset JSON into your container (e.g. `/secrets/app-keyset.json`), unseal it once at boot, and perform sub-microsecond in-memory encryptions:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/stfsy/go-envelope-encryption"
	"github.com/stfsy/go-envelope-encryption/keyset"
	"github.com/stfsy/go-envelope-encryption/kms"
)

func main() {
	ctx := context.Background()

	// 1. Connect to Cloud KMS Root Key (AWS KMS or GCP KMS)
	kmsMaster, err := kms.NewAWSKMSEncrypter("aws-kms://arn:aws:kms:us-east-1:123456789012:key/my-kek-id")
	// Or GCP Cloud KMS:
	// kmsMaster, err := kms.NewGCPKMSEncrypter(ctx, "gcp-kms://projects/my-proj/locations/global/keyRings/ring/cryptoKeys/kek")
	if err != nil {
		log.Fatalf("failed to connect to KMS: %v", err)
	}

	// 2. Unseal the mounted secret and generate ephemeral DEKs per payload
	// Zero network calls to KMS after boot; auto-reloads when secret rotates on disk.
	client, err := envelope.NewLocalEnvelopeFromMountedSecret(
		ctx,
		"/secrets/app-keyset.json",
		kmsMaster,
		keyset.AES256GCM,
		envelope.WithAutoReload(30*time.Second),
		envelope.WithReloadErrorHandler(func(err error) {
			log.Printf("Background keyset reload error: %v", err)
		}),
	)
	if err != nil {
		log.Fatalf("failed to initialize envelope client: %v", err)
	}
	defer client.Close()

	// 3. Encrypt sensitive data (with optional AAD for tenant isolation)
	plaintext := []byte("Sensitive customer PII data")
	tenantID := []byte("tenant_9874")

	ciphertext, err := client.Encrypt(ctx, plaintext, tenantID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Encrypted:", ciphertext)
	// Output: $tink$AXtsZ...

	// 4. Decrypt
	decrypted, err := client.Decrypt(ctx, ciphertext, tenantID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Decrypted:", string(decrypted))
}
```

---

### Pattern 2: Direct Cloud KMS Envelope (High-Compliance Mode)

For regulated workloads requiring a cloud HSM audit log entry for every individual record, use `NewDirectKMSEnvelope`:

```go
package main

import (
	"context"
	"log"

	"github.com/stfsy/go-envelope-encryption"
	"github.com/stfsy/go-envelope-encryption/keyset"
	"github.com/stfsy/go-envelope-encryption/kms"
)

func main() {
	ctx := context.Background()
	kmsAEAD, _ := kms.NewAWSKMSEncrypter("aws-kms://arn:aws:kms:us-east-1:123456789012:key/my-kek-id")

	// Each record wraps an ephemeral DEK directly via remote AWS KMS RPC
	client, err := envelope.NewDirectKMSEnvelope(kmsAEAD, keyset.AES256GCM)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ciphertext, _ := client.Encrypt(ctx, []byte("regulated payload"), []byte("audit-context"))
	plaintext, _ := client.Decrypt(ctx, ciphertext, []byte("audit-context"))
	log.Printf("Decrypted: %s", plaintext)
}
```

---

### Pattern 3: Local Development & Unit Testing (Mock KMS)

Test your application locally or in CI/CD without cloud credentials:

```go
package main

import (
	"context"
	"fmt"

	"github.com/stfsy/go-envelope-encryption"
	"github.com/stfsy/go-envelope-encryption/keyset"
	"github.com/stfsy/go-envelope-encryption/kms"
)

func main() {
	ctx := context.Background()

	// Auto-generates an in-memory mock KMS key
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")

	client, _ := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	defer client.Close()

	ct, _ := client.Encrypt(ctx, []byte("local test"), []byte("aad"))
	pt, _ := client.Decrypt(ctx, ct, []byte("aad"))
	fmt.Println(string(pt))
}
```

---

## 🔄 Keyset Lifecycle & SecOps (Python)

Tink keysets are language-agnostic. Security and DevOps teams can generate and rotate KMS-encrypted keysets using Python in CI/CD pipelines or AWS Lambda.

### 1. Install Python Tooling Requirements

```bash
pip install tink boto3 google-cloud-kms
```

### 2. Generate Initial Keyset

```bash
python scripts/create_keyset.py \
    --kms-uri "aws-kms://arn:aws:kms:us-east-1:123456789012:key/my-key-id" \
    --out app-keyset.json \
    --template AES256_GCM
```

Upload `app-keyset.json` to **AWS Secrets Manager** or **GCP Secret Manager**, and mount it into your Cloud Run or ECS service.

### 3. Zero-Downtime Key Rotation

When rotating keys:
1. `rotate_keyset.py` unwraps the existing keyset using KMS.
2. It generates a new key and promotes it to `PRIMARY`.
3. Existing keys remain `ENABLED` so historical records continue to decrypt seamlessly.
4. It re-encrypts the updated keyset under KMS.

```bash
python scripts/rotate_keyset.py \
    --kms-uri "aws-kms://arn:aws:kms:us-east-1:123456789012:key/my-key-id" \
    --in app-keyset.json \
    --out app-keyset-v2.json
```

---

## ⚡ Zero-Restart In-Memory Hot-Reloading

In Kubernetes and Google Cloud Run, mounted secret files are updated automatically on the filesystem when a new secret version is published. Enable `WithAutoReload` to detect updates and hot-reload in memory without downtime:

```go
client, err := envelope.NewFromMountedSecret(
    ctx, 
    "/secrets/app-keyset.json", 
    kmsMaster,
    envelope.WithAutoReload(5 * time.Minute), // Polls file modtime
)
```

---

## 📊 Benchmarks

Measured on an Intel Core Ultra 9 285H running Go 1.26 under Windows/AMD64:

| Benchmark Operation | Throughput | Latency | Heap Allocations |
| :--- | :--- | :--- | :--- |
| `BenchmarkDecryptBytes` | **~570,000 ops/sec** | **2.0 µs / op** | 13 allocs/op (1.8 KB) |
| `BenchmarkDecrypt` (String) | **~567,000 ops/sec** | **2.1 µs / op** | 14 allocs/op (1.9 KB) |
| `BenchmarkEncryptBytes` | **~341,000 ops/sec** | **3.4 µs / op** | 24 allocs/op (2.5 KB) |
| `BenchmarkEncrypt` (String) | **~294,000 ops/sec** | **3.9 µs / op** | 27 allocs/op (3.2 KB) |

---

## 📄 License

MIT License. Copyright (c) 2026 Seatling.
