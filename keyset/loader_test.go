package keyset_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stfsy/go-envelope-encryption/keyset"
	"github.com/stfsy/go-envelope-encryption/kms"
	"github.com/tink-crypto/tink-go/v2/aead"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestKeysetGenerateAndLoad(t *testing.T) {
	mockAEAD, _, err := kms.NewMockKMSEncrypter("")
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}

	buf := new(bytes.Buffer)
	err = keyset.GenerateEncryptedKeyset(buf, mockAEAD, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("GenerateEncryptedKeyset failed: %v", err)
	}

	// Load back
	handle, err := keyset.LoadEncryptedKeyset(bytes.NewReader(buf.Bytes()), mockAEAD)
	if err != nil {
		t.Fatalf("LoadEncryptedKeyset failed: %v", err)
	}

	primitive, err := aead.New(handle)
	if err != nil {
		t.Fatalf("failed to create AEAD primitive from keyset handle: %v", err)
	}

	plaintext := []byte("confidential customer payload")
	aad := []byte("customer-102")

	ciphertext, err := primitive.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := primitive.Decrypt(ciphertext, aad)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted mismatch: got %s, want %s", decrypted, plaintext)
	}
}

func TestKeysetLoadMountedSecret(t *testing.T) {
	mockAEAD, _, err := kms.NewMockKMSEncrypter("")
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "app-keyset.json")

	f, err := os.Create(secretPath)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	err = keyset.GenerateEncryptedKeyset(f, mockAEAD, keyset.XChaCha20Poly1305)
	if closeErr := f.Close(); closeErr != nil {
		t.Fatalf("failed to close file: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("GenerateEncryptedKeyset failed: %v", err)
	}

	handle, err := keyset.LoadMountedSecret(secretPath, mockAEAD)
	if err != nil {
		t.Fatalf("LoadMountedSecret failed: %v", err)
	}

	primitive, err := aead.New(handle)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	data := []byte("test-data")
	ct, err := primitive.Encrypt(data, nil)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	pt, err := primitive.Decrypt(ct, nil)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if string(pt) != string(data) {
		t.Fatalf("mismatch: got %s, want %s", pt, data)
	}
}

func TestKeysetRotation(t *testing.T) {
	mockAEAD, _, err := kms.NewMockKMSEncrypter("")
	if err != nil {
		t.Fatalf("failed to create mock KMS: %v", err)
	}

	// 1. Generate initial keyset V1
	v1Buf := new(bytes.Buffer)
	err = keyset.GenerateEncryptedKeyset(v1Buf, mockAEAD, keyset.AES256GCM)
	if err != nil {
		t.Fatalf("GenerateEncryptedKeyset V1 failed: %v", err)
	}

	v1Bytes := v1Buf.Bytes()

	// 2. Encrypt record with V1
	handle1, err := keyset.LoadEncryptedKeyset(bytes.NewReader(v1Bytes), mockAEAD)
	if err != nil {
		t.Fatalf("Load V1 failed: %v", err)
	}
	primitive1, _ := aead.New(handle1)

	oldRecord := []byte("Record encrypted with Key 1")
	oldCiphertext, err := primitive1.Encrypt(oldRecord, []byte("rec-1"))
	if err != nil {
		t.Fatalf("encrypt with V1 failed: %v", err)
	}

	// 3. Rotate to V2 (adds Key 2, promotes to primary, keeps Key 1 enabled)
	v2Buf := new(bytes.Buffer)
	err = keyset.RotateEncryptedKeyset(bytes.NewReader(v1Bytes), v2Buf, mockAEAD, keyset.XChaCha20Poly1305)
	if err != nil {
		t.Fatalf("RotateEncryptedKeyset failed: %v", err)
	}

	// 4. Load rotated Keyset V2
	handle2, err := keyset.LoadEncryptedKeyset(bytes.NewReader(v2Buf.Bytes()), mockAEAD)
	if err != nil {
		t.Fatalf("Load V2 failed: %v", err)
	}
	primitive2, _ := aead.New(handle2)

	// 5. Decrypt historical record encrypted with Key 1 using Keyset V2
	decryptedOld, err := primitive2.Decrypt(oldCiphertext, []byte("rec-1"))
	if err != nil {
		t.Fatalf("failed to decrypt old record with rotated keyset: %v", err)
	}
	if string(decryptedOld) != string(oldRecord) {
		t.Fatalf("old record mismatch: got %s, want %s", decryptedOld, oldRecord)
	}

	// 6. Encrypt new record with Keyset V2 (uses Key 2)
	newRecord := []byte("Record encrypted with Key 2")
	newCiphertext, err := primitive2.Encrypt(newRecord, []byte("rec-2"))
	if err != nil {
		t.Fatalf("encrypt with V2 failed: %v", err)
	}

	decryptedNew, err := primitive2.Decrypt(newCiphertext, []byte("rec-2"))
	if err != nil {
		t.Fatalf("failed to decrypt new record: %v", err)
	}
	if string(decryptedNew) != string(newRecord) {
		t.Fatalf("new record mismatch: got %s, want %s", decryptedNew, newRecord)
	}
}

func TestRejectNonAEADTemplate(t *testing.T) {
	mockAEAD, _, _ := kms.NewMockKMSEncrypter("")
	badTemplate := &tinkpb.KeyTemplate{
		TypeUrl: "type.googleapis.com/google.crypto.tink.HmacKey",
	}

	buf := new(bytes.Buffer)
	err := keyset.GenerateEncryptedKeyset(buf, mockAEAD, badTemplate)
	if !errors.Is(err, keyset.ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType on Generate, got: %v", err)
	}

	// Valid initial keyset
	validBuf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(validBuf, mockAEAD, keyset.AES256GCM)

	// Try rotating with bad template
	outBuf := new(bytes.Buffer)
	err = keyset.RotateEncryptedKeyset(bytes.NewReader(validBuf.Bytes()), outBuf, mockAEAD, badTemplate)
	if !errors.Is(err, keyset.ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType on Rotate, got: %v", err)
	}
}

func TestValidateAEADTemplateNilAndMalformed(t *testing.T) {
	// 1. nil template must be rejected
	err := keyset.ValidateAEADTemplate(nil)
	if !errors.Is(err, keyset.ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType for nil template, got: %v", err)
	}

	// 2. Valid TypeUrl but empty/corrupt Value
	corruptTemplate := &tinkpb.KeyTemplate{
		TypeUrl: "type.googleapis.com/google.crypto.tink.AesGcmKey",
		Value:   []byte("invalid-protobuf-bytes"),
	}
	err = keyset.ValidateAEADTemplate(corruptTemplate)
	if !errors.Is(err, keyset.ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType for malformed template Value, got: %v", err)
	}

	// 3. Valid templates
	if err := keyset.ValidateAEADTemplate(keyset.AES256GCM); err != nil {
		t.Fatalf("expected AES256GCM to be valid, got: %v", err)
	}
	if err := keyset.ValidateAEADTemplate(keyset.XChaCha20Poly1305); err != nil {
		t.Fatalf("expected XChaCha20Poly1305 to be valid, got: %v", err)
	}
}

func TestKeysetContextCancellation(t *testing.T) {
	mockAEAD, _, _ := kms.NewMockKMSEncrypter("")
	validBuf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(validBuf, mockAEAD, keyset.AES256GCM)

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	// 1. LoadEncryptedKeysetWithContext with canceled context
	_, err := keyset.LoadEncryptedKeysetWithContext(canceledCtx, bytes.NewReader(validBuf.Bytes()), mockAEAD)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	// 2. LoadEncryptedKeysetWithContext with nil context
	_, err = keyset.LoadEncryptedKeysetWithContext(nil, bytes.NewReader(validBuf.Bytes()), mockAEAD)
	if err == nil {
		t.Fatal("expected error for nil context on LoadEncryptedKeysetWithContext")
	}

	// 3. LoadMountedSecretWithContext with canceled context
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "secret.json")
	if err := os.WriteFile(path, validBuf.Bytes(), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err = keyset.LoadMountedSecretWithContext(canceledCtx, path, mockAEAD)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on LoadMountedSecretWithContext, got: %v", err)
	}

	// 4. LoadMountedSecretWithContext with nil context and empty path
	_, err = keyset.LoadMountedSecretWithContext(nil, path, mockAEAD)
	if err == nil {
		t.Fatal("expected error for nil context on LoadMountedSecretWithContext")
	}

	_, err = keyset.LoadMountedSecretWithContext(context.Background(), "", mockAEAD)
	if !errors.Is(err, keyset.ErrEmptyPath) {
		t.Fatalf("expected ErrEmptyPath, got: %v", err)
	}
}

func TestRotateEncryptedKeysetNilWriterAndReader(t *testing.T) {
	mockAEAD, _, _ := kms.NewMockKMSEncrypter("")
	validBuf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(validBuf, mockAEAD, keyset.AES256GCM)

	// nil writer must not panic
	err := keyset.RotateEncryptedKeyset(bytes.NewReader(validBuf.Bytes()), nil, mockAEAD, keyset.AES256GCM)
	if err == nil || !errors.Is(err, keyset.ErrInvalidKeyset) {
		t.Fatalf("expected ErrInvalidKeyset for nil writer, got: %v", err)
	}

	// nil reader must not panic
	outBuf := new(bytes.Buffer)
	err = keyset.RotateEncryptedKeyset(nil, outBuf, mockAEAD, keyset.AES256GCM)
	if err == nil || !errors.Is(err, keyset.ErrInvalidKeyset) {
		t.Fatalf("expected ErrInvalidKeyset for nil reader, got: %v", err)
	}
}

func TestLoadEncryptedKeysetBoundedReader(t *testing.T) {
	mockAEAD, _, _ := kms.NewMockKMSEncrypter("")

	// Oversized reader exceeding MaxKeysetJSONSize (4 MiB)
	oversizedReader := io.LimitReader(&infiniteZeros{}, keyset.MaxKeysetJSONSize+100)
	_, err := keyset.LoadEncryptedKeyset(oversizedReader, mockAEAD)
	if !errors.Is(err, keyset.ErrKeysetTooLarge) {
		t.Fatalf("expected ErrKeysetTooLarge for oversized input, got: %v", err)
	}
}

type infiniteZeros struct{}

func (i *infiniteZeros) Read(p []byte) (n int, err error) {
	for j := range p {
		p[j] = ' '
	}
	return len(p), nil
}
