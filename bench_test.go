package envelope_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stfsy/go-envelope-encryption"
	"github.com/stfsy/go-envelope-encryption/keyset"
	"github.com/stfsy/go-envelope-encryption/kms"
	"github.com/tink-crypto/tink-go/v2/aead"
)

func BenchmarkEncrypt(b *testing.B) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	buf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(buf, mockKMS, keyset.AES256GCM)
	kh, _ := keyset.LoadEncryptedKeyset(bytes.NewReader(buf.Bytes()), mockKMS)
	kekAEAD, _ := aead.New(kh)

	client, err := envelope.NewLocalEnvelope(kekAEAD, keyset.AES256GCM)
	if err != nil {
		b.Fatalf("NewLocalEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload := []byte("Sensitive customer document payload to encrypt in benchmark")
	aad := []byte("tenant-benchmark-100")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Encrypt(ctx, payload, aad)
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	buf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(buf, mockKMS, keyset.AES256GCM)
	kh, _ := keyset.LoadEncryptedKeyset(bytes.NewReader(buf.Bytes()), mockKMS)
	kekAEAD, _ := aead.New(kh)

	client, err := envelope.NewLocalEnvelope(kekAEAD, keyset.AES256GCM)
	if err != nil {
		b.Fatalf("NewLocalEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload := []byte("Sensitive customer document payload to encrypt in benchmark")
	aad := []byte("tenant-benchmark-100")

	ciphertext, err := client.Encrypt(ctx, payload, aad)
	if err != nil {
		b.Fatalf("setup Encrypt failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.Decrypt(ctx, ciphertext, aad)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
	}
}

func BenchmarkEncryptBytes(b *testing.B) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	buf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(buf, mockKMS, keyset.AES256GCM)
	kh, _ := keyset.LoadEncryptedKeyset(bytes.NewReader(buf.Bytes()), mockKMS)
	kekAEAD, _ := aead.New(kh)

	client, err := envelope.NewLocalEnvelope(kekAEAD, keyset.AES256GCM)
	if err != nil {
		b.Fatalf("NewLocalEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload := []byte("Sensitive customer document payload to encrypt in benchmark")
	aad := []byte("tenant-benchmark-100")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.EncryptBytes(ctx, payload, aad)
		if err != nil {
			b.Fatalf("EncryptBytes failed: %v", err)
		}
	}
}

func BenchmarkDecryptBytes(b *testing.B) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	buf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(buf, mockKMS, keyset.AES256GCM)
	kh, _ := keyset.LoadEncryptedKeyset(bytes.NewReader(buf.Bytes()), mockKMS)
	kekAEAD, _ := aead.New(kh)

	client, err := envelope.NewLocalEnvelope(kekAEAD, keyset.AES256GCM)
	if err != nil {
		b.Fatalf("NewLocalEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload := []byte("Sensitive customer document payload to encrypt in benchmark")
	aad := []byte("tenant-benchmark-100")

	rawCiphertext, err := client.EncryptBytes(ctx, payload, aad)
	if err != nil {
		b.Fatalf("setup EncryptBytes failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.DecryptBytes(ctx, rawCiphertext, aad)
		if err != nil {
			b.Fatalf("DecryptBytes failed: %v", err)
		}
	}
}

func BenchmarkDecryptWireBytes(b *testing.B) {
	ctx := context.Background()
	mockKMS, _, _ := kms.NewMockKMSEncrypter("")
	buf := new(bytes.Buffer)
	_ = keyset.GenerateEncryptedKeyset(buf, mockKMS, keyset.AES256GCM)
	kh, _ := keyset.LoadEncryptedKeyset(bytes.NewReader(buf.Bytes()), mockKMS)
	kekAEAD, _ := aead.New(kh)

	client, err := envelope.NewLocalEnvelope(kekAEAD, keyset.AES256GCM)
	if err != nil {
		b.Fatalf("NewLocalEnvelope failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload := []byte("Sensitive customer document payload to encrypt in benchmark")
	aad := []byte("tenant-benchmark-100")

	ciphertextStr, err := client.Encrypt(ctx, payload, aad)
	if err != nil {
		b.Fatalf("setup Encrypt failed: %v", err)
	}
	wireBytes := []byte(ciphertextStr)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := client.DecryptWireBytes(ctx, wireBytes, aad)
		if err != nil {
			b.Fatalf("DecryptWireBytes failed: %v", err)
		}
	}
}

func BenchmarkFormatWire(b *testing.B) {
	raw := []byte("arbitrary-binary-tink-envelope-dek-and-payload-bytes-12345678901234567890")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = envelope.FormatWire(raw)
	}
}

func BenchmarkParseWire(b *testing.B) {
	raw := []byte("arbitrary-binary-tink-envelope-dek-and-payload-bytes-12345678901234567890")
	wireStr := envelope.FormatWire(raw)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := envelope.ParseWire(wireStr)
		if err != nil {
			b.Fatalf("ParseWire failed: %v", err)
		}
	}
}

func BenchmarkParseWireBytes(b *testing.B) {
	raw := []byte("arbitrary-binary-tink-envelope-dek-and-payload-bytes-12345678901234567890")
	wireBytes := []byte(envelope.FormatWire(raw))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := envelope.ParseWireBytes(wireBytes)
		if err != nil {
			b.Fatalf("ParseWireBytes failed: %v", err)
		}
	}
}
