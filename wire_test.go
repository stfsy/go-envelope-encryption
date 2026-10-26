package envelope_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stfsy/go-envelope-encryption"
)

func TestWireFormatAndParse(t *testing.T) {
	rawBytes := []byte("arbitrary-binary-tink-envelope-payload-\x00\x01\x02\xff")
	wireStr := envelope.FormatWire(rawBytes)

	if !strings.HasPrefix(wireStr, envelope.Prefix) {
		t.Fatalf("expected prefix %q, got: %s", envelope.Prefix, wireStr)
	}

	parsed, err := envelope.ParseWire(wireStr)
	if err != nil {
		t.Fatalf("ParseWire failed: %v", err)
	}

	if !bytes.Equal(parsed, rawBytes) {
		t.Fatalf("parsed mismatch: got %v, want %v", parsed, rawBytes)
	}
}

func TestWireURLSafeAndEdgeCases(t *testing.T) {
	// 1. URL-safe base64 payload containing '-' and '_'
	raw := []byte{0xfb, 0xff, 0xbe}
	urlSafePadded := "$tink$-_--"
	parsed, err := envelope.ParseWire(urlSafePadded)
	if err != nil {
		t.Fatalf("ParseWire URL-safe padded failed: %v", err)
	}
	if !bytes.Equal(parsed, raw) {
		t.Fatalf("URL-safe parsed mismatch: got %x, want %x", parsed, raw)
	}

	// 2. URL-safe unpadded
	raw2 := []byte{0xfb, 0xff}
	urlSafeRaw := "$tink$-_8"
	parsed2, err := envelope.ParseWire(urlSafeRaw)
	if err != nil {
		t.Fatalf("ParseWire URL-safe raw failed: %v", err)
	}
	if !bytes.Equal(parsed2, raw2) {
		t.Fatalf("URL-safe raw parsed mismatch: got %x, want %x", parsed2, raw2)
	}

	// 3. Test arbitrary binary encoded with base64.URLEncoding
	sample := []byte("arbitrary binary with \xff\xfe\xfd URL-safe characters")
	encodedURL := envelope.Prefix + base64.URLEncoding.EncodeToString(sample)
	parsedSample, err := envelope.ParseWire(encodedURL)
	if err != nil {
		t.Fatalf("ParseWire encodedURL failed: %v", err)
	}
	if !bytes.Equal(parsedSample, sample) {
		t.Fatalf("encodedURL parsed mismatch: got %q, want %q", parsedSample, sample)
	}
}

func TestParseWireBytes(t *testing.T) {
	raw := []byte("byte-slice-test-payload-0123456789")
	wireStr := envelope.FormatWire(raw)
	wireBytes := []byte(wireStr)

	parsed, err := envelope.ParseWireBytes(wireBytes)
	if err != nil {
		t.Fatalf("ParseWireBytes failed: %v", err)
	}
	if !bytes.Equal(parsed, raw) {
		t.Fatalf("ParseWireBytes mismatch: got %v, want %v", parsed, raw)
	}

	// Empty bytes
	_, err = envelope.ParseWireBytes([]byte{})
	if err != envelope.ErrEmptyCiphertext {
		t.Fatalf("expected ErrEmptyCiphertext for empty slice, got: %v", err)
	}

	// Invalid prefix
	_, err = envelope.ParseWireBytes([]byte("bad-prefix"))
	if err != envelope.ErrInvalidMagicPrefix {
		t.Fatalf("expected ErrInvalidMagicPrefix, got: %v", err)
	}
}

func FuzzWire(f *testing.F) {
	seeds := [][]byte{
		[]byte("hello world"),
		[]byte(""),
		[]byte("\x00\x01\x02\x03\x04\x05"),
		[]byte("$tink$AA=="),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		wireStr := envelope.FormatWire(data)
		parsed, err := envelope.ParseWire(wireStr)
		if err != nil {
			t.Fatalf("roundtrip failed: %v", err)
		}
		if !bytes.Equal(parsed, data) {
			t.Fatalf("data mismatch on fuzz roundtrip")
		}

		// Also verify ParseWireBytes roundtrip
		parsedBytes, err := envelope.ParseWireBytes([]byte(wireStr))
		if err != nil {
			t.Fatalf("byte roundtrip failed: %v", err)
		}
		if !bytes.Equal(parsedBytes, data) {
			t.Fatalf("data mismatch on byte fuzz roundtrip")
		}

		// Also test fuzzing the parser directly with arbitrary string and byte inputs
		_, _ = envelope.ParseWire(string(data))
		_, _ = envelope.ParseWireBytes(data)
	})
}
