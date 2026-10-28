package envelope_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stfsy/go-envelope-encryption"
	"github.com/stfsy/go-envelope-encryption/keyset"
	"github.com/stfsy/go-envelope-encryption/kms"
	"github.com/tink-crypto/tink-go/v2/aead"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestLocalEnvelopeEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, err := kms.NewMockKMSEncrypter("")
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}

	// 1. Create Tier 2 Keyset
	kh, err := keyset.LoadEncryptedKeyset(bytes.NewReader(mustGenerateKeyset(t, mockKMS)), mockKMS)
	if err != nil {
		t.Fatalf("failed to load keyset: %v", err)
	}
	kekAEAD, err := aead.New(kh)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	// 2. Initialize Local Envelope client
	client, err := envelope.NewLocalEnvelope(kekAEAD, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("NewLocalEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload := []byte("Sensitive customer document payload")
	aad := []byte("tenant-42-doc-99")

	// 3. Encrypt to modular wire string
	ciphertext, err := client.Encrypt(ctx, payload, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if !strings.HasPrefix(ciphertext, envelope.Prefix) {
		t.Fatalf("expected wire prefix %q, got: %s", envelope.Prefix, ciphertext)
	}

	// 4. Decrypt
	decrypted, err := client.Decrypt(ctx, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Fatalf("decrypted mismatch: got %q, want %q", decrypted, payload)
	}

	// 5. Mismatched AAD must fail
	_, err = client.Decrypt(ctx, ciphertext, []byte("wrong-tenant"))
	if !errors.Is(err, envelope.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed for bad AAD, got: %v", err)
	}

	// 6. Tampered ciphertext must fail
	tampered := ciphertext[:len(ciphertext)-4] + "AAAA"
	_, err = client.Decrypt(ctx, tampered, aad)
	if !errors.Is(err, envelope.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed for tampered ciphertext, got: %v", err)
	}

	// 7. DecryptWireBytes (zero-allocation byte slice path)
	decryptedBytes, err := client.DecryptWireBytes(ctx, []byte(ciphertext), aad)
	if err != nil {
		t.Fatalf("DecryptWireBytes failed: %v", err)
	}
	if !bytes.Equal(decryptedBytes, payload) {
		t.Fatalf("DecryptWireBytes mismatch: got %q, want %q", decryptedBytes, payload)
	}
}

func TestDirectKMSEnvelope(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, err := kms.NewMockKMSEncrypter("")
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}

	client, err := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("NewDirectKMSEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	data := []byte("Cloud HSM direct payload")
	aad := []byte("audit-log-ref")

	ct, err := client.Encrypt(ctx, data, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	pt, err := client.Decrypt(ctx, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(pt, data) {
		t.Fatalf("mismatch: got %s, want %s", pt, data)
	}
}

func TestMountedSecretWithRotation(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, err := kms.NewMockKMSEncrypter("")
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "app-keyset.json")

	// 1. Write Keyset V1 to mounted path
	v1File, err := os.Create(secretPath)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	err = keyset.GenerateEncryptedKeyset(v1File, mockKMS, keyset.AES256GCM)
	if closeErr := v1File.Close(); closeErr != nil {
		t.Fatalf("failed to close file: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("failed to write V1: %v", err)
	}

	// 2. Initialize Client from mounted secret
	client, err := envelope.NewFromMountedSecret(ctx, secretPath, mockKMS)
	if err != nil {
		t.Fatalf("NewFromMountedSecret failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	doc1 := []byte("Document encrypted pre-rotation")
	c1, err := client.Encrypt(ctx, doc1)
	if err != nil {
		t.Fatalf("encrypt doc1 failed: %v", err)
	}

	// 3. Rotate Keyset to V2 on the filesystem
	v1Bytes, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read v1 failed: %v", err)
	}

	v2Buf := new(bytes.Buffer)
	err = keyset.RotateEncryptedKeyset(bytes.NewReader(v1Bytes), v2Buf, mockKMS, keyset.XChaCha20Poly1305)
	if err != nil {
		t.Fatalf("rotate failed: %v", err)
	}

	if err := os.WriteFile(secretPath, v2Buf.Bytes(), 0600); err != nil {
		t.Fatalf("write v2 failed: %v", err)
	}

	// 4. Manually reload client
	if err := client.Reload(secretPath, mockKMS); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// 5. Encrypt doc2 post-rotation
	doc2 := []byte("Document encrypted post-rotation")
	c2, err := client.Encrypt(ctx, doc2)
	if err != nil {
		t.Fatalf("encrypt doc2 failed: %v", err)
	}

	// 6. Seamless dual-read: decrypt BOTH doc1 and doc2
	d1, err := client.Decrypt(ctx, c1)
	if err != nil {
		t.Fatalf("decrypt doc1 post-rotation failed: %v", err)
	}
	if !bytes.Equal(d1, doc1) {
		t.Fatalf("doc1 mismatch: got %s, want %s", d1, doc1)
	}

	d2, err := client.Decrypt(ctx, c2)
	if err != nil {
		t.Fatalf("decrypt doc2 failed: %v", err)
	}
	if !bytes.Equal(d2, doc2) {
		t.Fatalf("doc2 mismatch: got %s, want %s", d2, doc2)
	}
}

func TestAutoReloader(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, err := kms.NewMockKMSEncrypter("")
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "auto-keyset.json")

	// Write V1
	v1Buf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(v1Buf, mockKMS, keyset.AES256GCM)
	_ = os.WriteFile(secretPath, v1Buf.Bytes(), 0600)

	// Create client with 15ms auto-reload interval
	client, err := envelope.NewFromMountedSecret(ctx, secretPath, mockKMS, envelope.WithAutoReload(15*time.Millisecond))
	if err != nil {
		t.Fatalf("NewFromMountedSecret failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	doc1 := []byte("auto-reload doc1")
	c1, err := client.Encrypt(ctx, doc1)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Rotate on disk and touch modtime
	v2Buf := new(bytes.Buffer)
	_ = keyset.RotateEncryptedKeyset(bytes.NewReader(v1Buf.Bytes()), v2Buf, mockKMS, keyset.XChaCha20Poly1305)
	time.Sleep(50 * time.Millisecond)
	_ = os.WriteFile(secretPath, v2Buf.Bytes(), 0600)

	// Wait for auto-reloader to pick it up
	time.Sleep(100 * time.Millisecond)

	// Encrypt doc2
	doc2 := []byte("auto-reload doc2")
	c2, err := client.Encrypt(ctx, doc2)
	if err != nil {
		t.Fatalf("encrypt doc2 failed: %v", err)
	}

	// Both must decrypt
	d1, err := client.Decrypt(ctx, c1)
	if err != nil || !bytes.Equal(d1, doc1) {
		t.Fatalf("decrypt doc1 failed: %v", err)
	}

	d2, err := client.Decrypt(ctx, c2)
	if err != nil || !bytes.Equal(d2, doc2) {
		t.Fatalf("decrypt doc2 failed: %v", err)
	}
}

func TestConcurrentUsage(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	v1Buf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(v1Buf, mockKMS, keyset.AES256GCM)

	kh, _ := keyset.LoadEncryptedKeyset(bytes.NewReader(v1Buf.Bytes()), mockKMS)
	client, err := envelope.NewFromKeysetHandle(kh)
	if err != nil {
		t.Fatalf("NewFromKeysetHandle failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	workers := 25
	iterations := 50
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := []byte("concurrent payload data")
			aad := []byte("aad-lock")

			for j := 0; j < iterations; j++ {
				ct, err := client.Encrypt(ctx, data, aad)
				if err != nil {
					t.Errorf("worker %d encrypt failed: %v", id, err)
					return
				}

				pt, err := client.Decrypt(ctx, ct, aad)
				if err != nil {
					t.Errorf("worker %d decrypt failed: %v", id, err)
					return
				}

				if !bytes.Equal(pt, data) {
					t.Errorf("worker %d data mismatch", id)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestWireFormatEdgeCases(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	client, _ := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	defer func() {
		_ = client.Close()
	}()

	// 1. Missing prefix
	_, err := client.Decrypt(ctx, "invalid-prefix-payload")
	if !errors.Is(err, envelope.ErrDecryptionFailed) || !errors.Is(err, envelope.ErrInvalidMagicPrefix) {
		t.Fatalf("expected ErrDecryptionFailed and ErrInvalidMagicPrefix for missing prefix, got: %v", err)
	}

	// 2. Empty string
	_, err = client.Decrypt(ctx, "")
	if !errors.Is(err, envelope.ErrDecryptionFailed) || !errors.Is(err, envelope.ErrEmptyCiphertext) {
		t.Fatalf("expected ErrDecryptionFailed and ErrEmptyCiphertext for empty string, got: %v", err)
	}

	// 3. Corrupted base64
	_, err = client.Decrypt(ctx, "$tink$not-valid-base64!!!")
	if !errors.Is(err, envelope.ErrDecryptionFailed) || !errors.Is(err, envelope.ErrInvalidEncoding) {
		t.Fatalf("expected ErrDecryptionFailed and ErrInvalidEncoding for bad base64, got: %v", err)
	}

	// 4. Nil plaintext
	_, err = client.Encrypt(ctx, nil)
	if !errors.Is(err, envelope.ErrNilPlaintext) {
		t.Fatalf("expected ErrNilPlaintext, got: %v", err)
	}

	// 5. Empty ciphertext in DecryptBytes
	_, err = client.DecryptBytes(ctx, []byte{})
	if !errors.Is(err, envelope.ErrEmptyCiphertext) {
		t.Fatalf("expected ErrEmptyCiphertext for empty slice, got: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	client, _ := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	defer func() {
		_ = client.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel context

	_, err := client.Encrypt(ctx, []byte("payload"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on Encrypt, got: %v", err)
	}

	_, err = client.Decrypt(ctx, "$tink$AAAA")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on Decrypt, got: %v", err)
	}

	_, err = client.EncryptBytes(ctx, []byte("payload"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on EncryptBytes, got: %v", err)
	}

	_, err = client.DecryptBytes(ctx, []byte("payload"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on DecryptBytes, got: %v", err)
	}

	// Pre-canceled context on mounted secret constructors
	_, err = envelope.NewFromMountedSecret(ctx, "nonexistent.json", mockKMS)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on NewFromMountedSecret, got: %v", err)
	}

	_, err = envelope.NewLocalEnvelopeFromMountedSecret(ctx, "nonexistent.json", mockKMS, keyset.AES256GCM)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on NewLocalEnvelopeFromMountedSecret, got: %v", err)
	}
}

func TestAutoReloaderErrorObservability(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "reload-err.json")

	// Write valid V1
	v1Buf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(v1Buf, mockKMS, keyset.AES256GCM)
	_ = os.WriteFile(secretPath, v1Buf.Bytes(), 0600)

	errChan := make(chan error, 1)
	errHandler := func(err error) {
		select {
		case errChan <- err:
		default:
		}
	}

	client, err := envelope.NewFromMountedSecret(
		ctx,
		secretPath,
		mockKMS,
		envelope.WithAutoReload(15*time.Millisecond),
		envelope.WithReloadErrorHandler(errHandler),
	)
	if err != nil {
		t.Fatalf("NewFromMountedSecret failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	// Overwrite with corrupted JSON to simulate bad secret sync
	time.Sleep(30 * time.Millisecond)
	_ = os.WriteFile(secretPath, []byte("not-valid-json-data"), 0600)

	select {
	case receivedErr := <-errChan:
		if receivedErr == nil {
			t.Fatal("expected non-nil error from reload error handler")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for reload error handler callback")
	}
}

func TestLocalEnvelopeFromMountedSecretWithRotation(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, err := kms.NewMockKMSEncrypter("")
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "kek_secret.json")

	// 1. Write initial KEK keyset
	if err := os.WriteFile(secretPath, mustGenerateKeyset(t, mockKMS), 0600); err != nil {
		t.Fatalf("failed to write initial secret: %v", err)
	}

	// 2. Initialize 2-tier local envelope client from mounted secret
	client, err := envelope.NewLocalEnvelopeFromMountedSecret(
		ctx,
		secretPath,
		mockKMS,
		keyset.AES256GCM,
		envelope.WithAutoReload(25*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewLocalEnvelopeFromMountedSecret failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload1 := []byte("payload before KEK rotation")
	aad1 := []byte("aad-v1")

	ct1, err := client.Encrypt(ctx, payload1, aad1)
	if err != nil {
		t.Fatalf("Encrypt 1 failed: %v", err)
	}

	pt1, err := client.Decrypt(ctx, ct1, aad1)
	if err != nil || !bytes.Equal(pt1, payload1) {
		t.Fatalf("Decrypt 1 failed or mismatch: %v", err)
	}

	// 3. Rotate KEK keyset on disk
	f, err := os.Open(secretPath)
	if err != nil {
		t.Fatalf("failed to open secret for rotation: %v", err)
	}
	var rotatedBuf bytes.Buffer
	if err := keyset.RotateEncryptedKeyset(f, &rotatedBuf, mockKMS, keyset.AES256GCM); err != nil {
		_ = f.Close()
		t.Fatalf("keyset rotation failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close secret: %v", err)
	}

	if err := os.WriteFile(secretPath, rotatedBuf.Bytes(), 0600); err != nil {
		t.Fatalf("failed to overwrite rotated secret: %v", err)
	}

	// 4. Allow auto-reloader to pick up the updated keyset
	time.Sleep(80 * time.Millisecond)

	payload2 := []byte("payload after KEK rotation with new primary key")
	aad2 := []byte("aad-v2")

	ct2, err := client.Encrypt(ctx, payload2, aad2)
	if err != nil {
		t.Fatalf("Encrypt 2 failed: %v", err)
	}

	// Decrypt payload2 with new key
	pt2, err := client.Decrypt(ctx, ct2, aad2)
	if err != nil || !bytes.Equal(pt2, payload2) {
		t.Fatalf("Decrypt 2 failed or mismatch: %v", err)
	}

	// Decrypt payload1 encrypted under old primary key (graceful backward compatibility)
	pt1After, err := client.Decrypt(ctx, ct1, aad1)
	if err != nil || !bytes.Equal(pt1After, payload1) {
		t.Fatalf("Decrypt 1 after rotation failed or mismatch: %v", err)
	}
}

func mustGenerateKeyset(t *testing.T, masterKey kmsAEAD) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	if err := keyset.GenerateEncryptedKeyset(buf, masterKey, keyset.AES256GCM); err != nil {
		t.Fatalf("mustGenerateKeyset failed: %v", err)
	}
	return buf.Bytes()
}

type kmsAEAD = interface {
	Encrypt(plaintext, associatedData []byte) ([]byte, error)
	Decrypt(ciphertext, associatedData []byte) ([]byte, error)
}

func TestRejectMultipleAAD(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	client, err := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("NewDirectKMSEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload := []byte("secret payload")
	aad1 := []byte("tenant-1")
	aad2 := []byte("user-2")

	// Encrypt
	_, err = client.Encrypt(ctx, payload, aad1, aad2)
	if !errors.Is(err, envelope.ErrInvalidAAD) {
		t.Fatalf("expected ErrInvalidAAD on Encrypt, got: %v", err)
	}

	// EncryptBytes
	_, err = client.EncryptBytes(ctx, payload, aad1, aad2)
	if !errors.Is(err, envelope.ErrInvalidAAD) {
		t.Fatalf("expected ErrInvalidAAD on EncryptBytes, got: %v", err)
	}

	// Valid encrypt to test decrypt with multiple AAD
	ct, err := client.Encrypt(ctx, payload, aad1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with multiple AAD
	_, err = client.Decrypt(ctx, ct, aad1, aad2)
	if !errors.Is(err, envelope.ErrInvalidAAD) {
		t.Fatalf("expected ErrInvalidAAD on Decrypt, got: %v", err)
	}

	// DecryptWireBytes with multiple AAD
	_, err = client.DecryptWireBytes(ctx, []byte(ct), aad1, aad2)
	if !errors.Is(err, envelope.ErrInvalidAAD) {
		t.Fatalf("expected ErrInvalidAAD on DecryptWireBytes, got: %v", err)
	}

	// DecryptBytes with multiple AAD
	rawBytes, _ := envelope.ParseWire(ct)
	_, err = client.DecryptBytes(ctx, rawBytes, aad1, aad2)
	if !errors.Is(err, envelope.ErrInvalidAAD) {
		t.Fatalf("expected ErrInvalidAAD on DecryptBytes, got: %v", err)
	}
}

func TestRejectOversizedEncrypt(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	client, err := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("NewDirectKMSEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	// 25 MiB payload will expand to > 32 MiB on wire
	largePayload := make([]byte, 25*1024*1024)
	_, err = client.Encrypt(ctx, largePayload)
	if !errors.Is(err, envelope.ErrCiphertextTooLarge) {
		t.Fatalf("expected ErrCiphertextTooLarge on Encrypt, got: %v", err)
	}
}

func TestInvalidDEKTemplateRejection(t *testing.T) {
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	badTemplate := &tinkpb.KeyTemplate{
		TypeUrl: "type.googleapis.com/google.crypto.tink.HmacKey",
	}

	_, err := envelope.NewLocalEnvelope(mockKMS, badTemplate)
	if !errors.Is(err, keyset.ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType on NewLocalEnvelope, got: %v", err)
	}

	_, err = envelope.NewDirectKMSEnvelope(mockKMS, badTemplate)
	if !errors.Is(err, keyset.ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType on NewDirectKMSEnvelope, got: %v", err)
	}
}

func TestReloadOnClosedClient(t *testing.T) {
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	client, err := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("NewDirectKMSEnvelope failed: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	err = client.Reload("dummy-path", mockKMS)
	if !errors.Is(err, envelope.ErrClientClosed) {
		t.Fatalf("expected ErrClientClosed on Reload after Close, got: %v", err)
	}
}

func TestContextCancellationDirectReturn(t *testing.T) {
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	client, err := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("NewDirectKMSEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled immediately

	_, err = client.DecryptBytes(ctx, []byte("some-ciphertext"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled directly, got: %v", err)
	}
	if errors.Is(err, envelope.ErrDecryptionFailed) {
		t.Fatalf("context cancellation should NOT be masked as ErrDecryptionFailed")
	}
}

func TestClientReloadNewSecretAndKMSKey(t *testing.T) {
	ctx := context.Background()
	mockKMS1, _, _ := kms.NewMockKMSEncrypter("")
	mockKMS2, _, _ := kms.NewMockKMSEncrypter("")

	tmpDir := t.TempDir()
	path1 := filepath.Join(tmpDir, "keyset1.json")
	path2 := filepath.Join(tmpDir, "keyset2.json")

	if err := os.WriteFile(path1, mustGenerateKeyset(t, mockKMS1), 0600); err != nil {
		t.Fatalf("failed to write keyset 1: %v", err)
	}
	if err := os.WriteFile(path2, mustGenerateKeyset(t, mockKMS2), 0600); err != nil {
		t.Fatalf("failed to write keyset 2: %v", err)
	}

	client, err := envelope.NewFromMountedSecret(ctx, path1, mockKMS1)
	if err != nil {
		t.Fatalf("NewFromMountedSecret failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload := []byte("hello world")
	_, err = client.Encrypt(ctx, payload)
	if err != nil {
		t.Fatalf("Encrypt ct1 failed: %v", err)
	}

	// Reload with new path and new KMS key
	if err := client.Reload(path2, mockKMS2); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Should be able to encrypt and decrypt with new keyset
	ct2, err := client.Encrypt(ctx, payload)
	if err != nil {
		t.Fatalf("Encrypt ct2 failed: %v", err)
	}

	decrypted2, err := client.Decrypt(ctx, ct2)
	if err != nil {
		t.Fatalf("Decrypt ct2 failed: %v", err)
	}
	if !bytes.Equal(decrypted2, payload) {
		t.Fatalf("payload mismatch")
	}

	// Test with NewLocalEnvelopeFromMountedSecret as well
	localClient, err := envelope.NewLocalEnvelopeFromMountedSecret(ctx, path1, mockKMS1, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("NewLocalEnvelopeFromMountedSecret failed: %v", err)
	}
	defer func() {
		_ = localClient.Close()
	}()

	if err := localClient.Reload(path2, mockKMS2); err != nil {
		t.Fatalf("localClient Reload failed: %v", err)
	}
	ctLocal, err := localClient.Encrypt(ctx, payload)
	if err != nil {
		t.Fatalf("localClient Encrypt failed: %v", err)
	}
	decLocal, err := localClient.Decrypt(ctx, ctLocal)
	if err != nil {
		t.Fatalf("localClient Decrypt failed: %v", err)
	}
	if !bytes.Equal(decLocal, payload) {
		t.Fatalf("localClient payload mismatch")
	}
}

func TestLocalEnvelopeReloadPreserves2Tier(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	tmpDir := t.TempDir()

	// Initial KEK keyset
	v1Data := mustGenerateKeyset(t, mockKMS)
	kh1, err := keyset.LoadEncryptedKeyset(bytes.NewReader(v1Data), mockKMS)
	if err != nil {
		t.Fatalf("load keyset v1 failed: %v", err)
	}
	kek1, err := aead.New(kh1)
	if err != nil {
		t.Fatalf("aead.New kek1 failed: %v", err)
	}

	client, err := envelope.NewLocalEnvelope(kek1, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("NewLocalEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	// Encrypt record 1 before reload
	payload1 := []byte("record-1-data")
	ct1, err := client.Encrypt(ctx, payload1)
	if err != nil {
		t.Fatalf("Encrypt 1 failed: %v", err)
	}

	// Rotate keyset: write rotated keyset to file (containing both key1 and key2)
	rotBuf := new(bytes.Buffer)
	if err := keyset.RotateEncryptedKeyset(bytes.NewReader(v1Data), rotBuf, mockKMS, keyset.AES256GCM); err != nil {
		t.Fatalf("RotateEncryptedKeyset failed: %v", err)
	}
	rotPath := filepath.Join(tmpDir, "rotated.json")
	if err := os.WriteFile(rotPath, rotBuf.Bytes(), 0600); err != nil {
		t.Fatalf("write rotated keyset failed: %v", err)
	}

	// Calling Reload on NewLocalEnvelope with rotated secret path & KMS key
	if err := client.Reload(rotPath, mockKMS); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Calling Reload with empty path should return ErrReloadUnsupported
	if err := client.Reload("", nil); !errors.Is(err, envelope.ErrReloadUnsupported) {
		t.Fatalf("expected ErrReloadUnsupported on empty path reload, got: %v", err)
	}

	// 1. Decrypt historical record 1
	dec1, err := client.Decrypt(ctx, ct1)
	if err != nil {
		t.Fatalf("failed to decrypt pre-reload record: %v", err)
	}
	if !bytes.Equal(dec1, payload1) {
		t.Fatalf("payload 1 mismatch")
	}

	// 2. Encrypt record 2 after reload
	payload2 := []byte("record-2-data")
	ct2, err := client.Encrypt(ctx, payload2)
	if err != nil {
		t.Fatalf("Encrypt 2 failed: %v", err)
	}
	dec2, err := client.Decrypt(ctx, ct2)
	if err != nil {
		t.Fatalf("Decrypt 2 failed: %v", err)
	}
	if !bytes.Equal(dec2, payload2) {
		t.Fatalf("payload 2 mismatch")
	}
}

func TestDirectKMSEnvelopeReloadUnsupported(t *testing.T) {
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	client, err := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("NewDirectKMSEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	err = client.Reload("dummy.json", mockKMS)
	if !errors.Is(err, envelope.ErrReloadUnsupported) {
		t.Fatalf("expected ErrReloadUnsupported on DirectKMSEnvelope.Reload, got: %v", err)
	}
}

func TestUnconfiguredReloadUnsupported(t *testing.T) {
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	client, err := envelope.New(mockKMS)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	err = client.Reload("dummy.json", mockKMS)
	if !errors.Is(err, envelope.ErrReloadUnsupported) {
		t.Fatalf("expected ErrReloadUnsupported on unconfigured Reload, got: %v", err)
	}
}

func TestPayloadSizeChecks(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	client, err := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("NewDirectKMSEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	oversized := make([]byte, envelope.MaxRawCiphertextLen+1)

	// 1. EncryptBytes oversized plaintext
	_, err = client.EncryptBytes(ctx, oversized)
	if !errors.Is(err, envelope.ErrCiphertextTooLarge) {
		t.Fatalf("expected ErrCiphertextTooLarge on EncryptBytes, got: %v", err)
	}

	// 2. Encrypt oversized plaintext
	_, err = client.Encrypt(ctx, oversized)
	if !errors.Is(err, envelope.ErrCiphertextTooLarge) {
		t.Fatalf("expected ErrCiphertextTooLarge on Encrypt, got: %v", err)
	}

	// 3. DecryptBytes oversized ciphertext
	_, err = client.DecryptBytes(ctx, oversized)
	if !errors.Is(err, envelope.ErrCiphertextTooLarge) || !errors.Is(err, envelope.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed wrapping ErrCiphertextTooLarge on DecryptBytes, got: %v", err)
	}
}

func TestAutoReloadSameSizeAndSameModTime(t *testing.T) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "keyset.json")

	// Initial keyset V1
	v1Data := mustGenerateKeyset(t, mockKMS)
	if err := os.WriteFile(secretPath, v1Data, 0600); err != nil {
		t.Fatalf("failed to write initial keyset: %v", err)
	}

	fi1, err := os.Stat(secretPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	initialModTime := fi1.ModTime()

	client, err := envelope.NewFromMountedSecret(
		ctx,
		secretPath,
		mockKMS,
		envelope.WithAutoReload(20*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewFromMountedSecret failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	// Initial payload encrypt & decrypt
	pt := []byte("secret-payload")
	ct1, err := client.Encrypt(ctx, pt)
	if err != nil {
		t.Fatalf("Encrypt 1 failed: %v", err)
	}

	// Generate different keyset V2 with identical size
	v2Data := mustGenerateKeyset(t, mockKMS)
	for len(v2Data) < len(v1Data) {
		v2Data = append(v2Data, ' ')
	}
	for len(v1Data) < len(v2Data) {
		v1Data = append(v1Data, ' ')
	}
	if len(v2Data) != len(v1Data) {
		v2Data = v2Data[:len(v1Data)]
	}

	// Write new data and force exact same ModTime
	if err := os.WriteFile(secretPath, v2Data, 0600); err != nil {
		t.Fatalf("failed to write v2 data: %v", err)
	}
	_ = os.Chtimes(secretPath, initialModTime, initialModTime)

	// Wait for auto-reloader to pick up hash change and reload
	var reloaded bool
	for start := time.Now(); time.Since(start) < 2*time.Second; {
		time.Sleep(50 * time.Millisecond)
		// Encrypt with client - if reloaded to V2, ct1 (encrypted with V1) will fail to decrypt!
		_, decErr := client.Decrypt(ctx, ct1)
		if decErr != nil {
			reloaded = true
			break
		}
	}

	if !reloaded {
		t.Fatal("expected auto-reloader to detect hash change and reload even with identical size and modtime")
	}
}

func FuzzEnvelopeDecrypt(f *testing.F) {
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	client, err := envelope.NewDirectKMSEnvelope(mockKMS, keyset.AES256GCM)
	if err != nil {
		f.Fatalf("NewDirectKMSEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	ctx := context.Background()

	// Seed valid envelope
	validCT, err := client.Encrypt(ctx, []byte("fuzz seed payload"), []byte("seed-aad"))
	if err != nil {
		f.Fatalf("seed Encrypt failed: %v", err)
	}

	f.Add([]byte(validCT), []byte("seed-aad"))
	f.Add([]byte("$tink$AAA"), []byte(""))
	f.Add([]byte("not-even-tink"), []byte(""))
	f.Add([]byte(""), []byte(""))

	f.Fuzz(func(t *testing.T, wire []byte, aad []byte) {
		_, _ = client.DecryptWireBytes(ctx, wire, aad)
		_, _ = client.Decrypt(ctx, string(wire), aad)
	})
}
