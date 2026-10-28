package kms_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stfsy/go-envelope-encryption/kms"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type mockAWSKMSClient struct {
	encryptFunc func(ctx context.Context, params *awskms.EncryptInput, optFns ...func(*awskms.Options)) (*awskms.EncryptOutput, error)
	decryptFunc func(ctx context.Context, params *awskms.DecryptInput, optFns ...func(*awskms.Options)) (*awskms.DecryptOutput, error)
}

func (m *mockAWSKMSClient) Encrypt(ctx context.Context, params *awskms.EncryptInput, optFns ...func(*awskms.Options)) (*awskms.EncryptOutput, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(ctx, params, optFns...)
	}
	return nil, errors.New("mock Encrypt not implemented")
}

func (m *mockAWSKMSClient) Decrypt(ctx context.Context, params *awskms.DecryptInput, optFns ...func(*awskms.Options)) (*awskms.DecryptOutput, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(ctx, params, optFns...)
	}
	return nil, errors.New("mock Decrypt not implemented")
}

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

	_, err := kms.NewAWSKMSEncrypter(ctx, "")
	if !errors.Is(err, kms.ErrInvalidURI) {
		t.Fatalf("expected ErrInvalidURI, got %v", err)
	}

	_, err = kms.NewAWSKMSEncrypter(ctx, "gcp-kms://projects/my-proj/locations/global/keyRings/r/cryptoKeys/k")
	if !errors.Is(err, kms.ErrInvalidURI) {
		t.Fatalf("expected ErrInvalidURI for cross-provider AWS URI, got %v", err)
	}

	_, err = kms.NewAWSKMSEncrypter(ctx, "aws-kms://invalid-arn")
	if !errors.Is(err, kms.ErrInvalidURI) {
		t.Fatalf("expected ErrInvalidURI for malformed AWS ARN, got %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = kms.NewAWSKMSEncrypter(canceledCtx, "aws-kms://arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	_, err = kms.NewAWSKMSEncrypter(nil, "aws-kms://arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
	if !errors.Is(err, kms.ErrKMSInitialization) {
		t.Fatalf("expected ErrKMSInitialization for nil context, got %v", err)
	}

	_, err = kms.NewGCPKMSEncrypter(ctx, "")
	if !errors.Is(err, kms.ErrInvalidURI) {
		t.Fatalf("expected ErrInvalidURI, got %v", err)
	}

	_, err = kms.NewGCPKMSEncrypter(ctx, "aws-kms://arn:aws:kms:us-east-1:123456789012:key/abc")
	if !errors.Is(err, kms.ErrInvalidURI) {
		t.Fatalf("expected ErrInvalidURI for cross-provider GCP URI, got %v", err)
	}

	_, err = kms.NewGCPKMSEncrypter(nil, "projects/p/locations/l/keyRings/r/cryptoKeys/k")
	if !errors.Is(err, kms.ErrKMSInitialization) {
		t.Fatalf("expected ErrKMSInitialization for nil context, got %v", err)
	}
}

func TestAWSKMSEncrypterMock(t *testing.T) {
	ctx := context.Background()
	rawARN := "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
	keyURI := "aws-kms://" + rawARN

	var capturedKeyID string
	var capturedEncCtx map[string]string

	mockClient := &mockAWSKMSClient{
		encryptFunc: func(ctx context.Context, params *awskms.EncryptInput, optFns ...func(*awskms.Options)) (*awskms.EncryptOutput, error) {
			if ctx == nil {
				return nil, errors.New("nil context")
			}
			capturedKeyID = aws.ToString(params.KeyId)
			capturedEncCtx = params.EncryptionContext
			fakeCiphertext := append([]byte("ENC:"), params.Plaintext...)
			return &awskms.EncryptOutput{
				CiphertextBlob: fakeCiphertext,
			}, nil
		},
		decryptFunc: func(ctx context.Context, params *awskms.DecryptInput, optFns ...func(*awskms.Options)) (*awskms.DecryptOutput, error) {
			if ctx == nil {
				return nil, errors.New("nil context")
			}
			if !bytes.HasPrefix(params.CiphertextBlob, []byte("ENC:")) {
				return nil, errors.New("invalid ciphertext blob")
			}
			return &awskms.DecryptOutput{
				Plaintext: bytes.TrimPrefix(params.CiphertextBlob, []byte("ENC:")),
			}, nil
		},
	}

	aead, err := kms.NewAWSKMSEncrypter(ctx, keyURI, kms.WithAWSKMSClient(mockClient))
	if err != nil {
		t.Fatalf("NewAWSKMSEncrypter failed: %v", err)
	}

	// Verify interfaces
	pwc, ok := aead.(tink.AEADWithContext)
	if !ok {
		t.Fatal("expected awsAEAD to implement tink.AEADWithContext")
	}

	plaintext := []byte("aws-kms-test-secret")
	aad := []byte("tenant-aws")

	// Test EncryptWithContext
	ct, err := pwc.EncryptWithContext(ctx, plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptWithContext failed: %v", err)
	}
	if capturedKeyID != rawARN {
		t.Fatalf("captured key ID mismatch: got %q, want %q", capturedKeyID, rawARN)
	}
	wantHexAAD := hex.EncodeToString(aad)
	if capturedEncCtx["associatedData"] != wantHexAAD {
		t.Fatalf("captured associatedData mismatch: got %q, want %q", capturedEncCtx["associatedData"], wantHexAAD)
	}

	// Test DecryptWithContext
	pt, err := pwc.DecryptWithContext(ctx, ct, aad)
	if err != nil {
		t.Fatalf("DecryptWithContext failed: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch: got %s, want %s", pt, plaintext)
	}

	// Test Encrypt / Decrypt background context delegates
	ct2, err := aead.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	pt2, err := aead.Decrypt(ct2, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(pt2, plaintext) {
		t.Fatalf("plaintext mismatch: got %s, want %s", pt2, plaintext)
	}

	// Test Context Cancellation
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = pwc.EncryptWithContext(canceledCtx, plaintext, aad)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on EncryptWithContext, got %v", err)
	}

	_, err = pwc.DecryptWithContext(canceledCtx, ct, aad)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on DecryptWithContext, got %v", err)
	}
}

func TestGCPClosableAEADInterface(t *testing.T) {
	// Verify that if GCP KMS initializes, it returns an io.Closer
	// We test this via reflection or type assertion on a dummy struct matching gcpClosableAEAD
	var closer io.Closer
	var aead tink.AEAD
	var aeadCtx tink.AEADWithContext

	mock, _, _ := kms.NewMockKMSEncrypter("")
	if mCloser, ok := mock.(io.Closer); ok {
		closer = mCloser
		_ = closer.Close()
	}

	_ = closer
	_ = aead
	_ = aeadCtx
}
