package kms_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stfsy/go-envelope-encryption/kms"
)

func TestMockKMSEncrypter(t *testing.T) {
	aead, uri, err := kms.NewMockKMSEncrypter("")
	if err != nil {
		t.Fatalf("NewMockKMSEncrypter failed: %v", err)
	}
	if uri == "" {
		t.Fatal("expected non-empty URI from mock KMS")
	}

	// Re-load same URI to verify consistency
	aead2, _, err := kms.NewMockKMSEncrypter(uri)
	if err != nil {
		t.Fatalf("reload mock KMS failed: %v", err)
	}

	plaintext := []byte("secret KMS payload")
	aad := []byte("tenant-42")

	ciphertext, err := aead.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("mock encrypt failed: %v", err)
	}

	decrypted, err := aead2.Decrypt(ciphertext, aad)
	if err != nil {
		t.Fatalf("mock decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted mismatch: got %s, want %s", decrypted, plaintext)
	}

	// Tampered AAD
	_, err = aead.Decrypt(ciphertext, []byte("wrong-aad"))
	if err == nil {
		t.Fatal("expected error on mismatched AAD, got nil")
	}
}

func TestKMSEncrypterInvalidURI(t *testing.T) {
	ctx := context.Background()

	_, err := kms.NewAWSKMSEncrypter("")
	if !errors.Is(err, kms.ErrInvalidURI) {
		t.Fatalf("expected ErrInvalidURI, got %v", err)
	}

	_, err = kms.NewGCPKMSEncrypter(ctx, "")
	if !errors.Is(err, kms.ErrInvalidURI) {
		t.Fatalf("expected ErrInvalidURI, got %v", err)
	}
}
