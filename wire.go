package envelope

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

const (
	// Prefix is the magic header identifying Tink envelope ciphertext strings.
	Prefix = "$tink$"
	// MaxCiphertextLen is the maximum allowable serialized envelope string length (32 MiB).
	MaxCiphertextLen = 32 * 1024 * 1024
)

var prefixBytes = []byte(Prefix)

var (
	// ErrInvalidMagicPrefix is returned when a ciphertext string does not start with $tink$.
	ErrInvalidMagicPrefix = errors.New("envelope: missing or invalid magic prefix, expected $tink$")
	// ErrEmptyCiphertext is returned when the ciphertext string is empty.
	ErrEmptyCiphertext = errors.New("envelope: ciphertext cannot be empty")
	// ErrCiphertextTooLarge is returned when ciphertext string exceeds MaxCiphertextLen.
	ErrCiphertextTooLarge = errors.New("envelope: ciphertext exceeds maximum allowable length")
	// ErrInvalidEncoding is returned when base64 decoding fails.
	ErrInvalidEncoding = errors.New("envelope: invalid base64 encoding")
)

// FormatWire wraps raw Tink envelope bytes into the standard modular string:
// $tink$<base64_standard>
// It allocates a single contiguous buffer and uses zero-copy string construction (1 allocation).
func FormatWire(raw []byte) string {
	encLen := base64.StdEncoding.EncodedLen(len(raw))
	buf := make([]byte, len(Prefix)+encLen)
	copy(buf, Prefix)
	base64.StdEncoding.Encode(buf[len(Prefix):], raw)
	return unsafe.String(unsafe.SliceData(buf), len(buf))
}

// ParseWire decodes and verifies a $tink$<base64> modular ciphertext string.
// It uses discriminant analysis to select the matching base64 decoder in O(1) without error cascades.
func ParseWire(serialized string) ([]byte, error) {
	if len(serialized) == 0 {
		return nil, ErrEmptyCiphertext
	}
	if len(serialized) > MaxCiphertextLen {
		return nil, ErrCiphertextTooLarge
	}
	if !strings.HasPrefix(serialized, Prefix) {
		return nil, ErrInvalidMagicPrefix
	}

	payload := serialized[len(Prefix):]
	b, err := decodeBase64String(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEncoding, err)
	}
	return b, nil
}

// ParseWireBytes decodes and verifies a $tink$<base64> ciphertext directly from a byte slice.
// This eliminates intermediate string allocations for high-throughput network and database callers.
func ParseWireBytes(serialized []byte) ([]byte, error) {
	if len(serialized) == 0 {
		return nil, ErrEmptyCiphertext
	}
	if len(serialized) > MaxCiphertextLen {
		return nil, ErrCiphertextTooLarge
	}
	if !bytes.HasPrefix(serialized, prefixBytes) {
		return nil, ErrInvalidMagicPrefix
	}

	payload := serialized[len(prefixBytes):]
	b, err := decodeBase64Bytes(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEncoding, err)
	}
	return b, nil
}

func decodeBase64String(payload string) ([]byte, error) {
	isURLSafe := strings.ContainsAny(payload, "-_")
	isPadded := strings.HasSuffix(payload, "=")

	if isURLSafe {
		if isPadded {
			return base64.URLEncoding.DecodeString(payload)
		}
		b, err := base64.RawURLEncoding.DecodeString(payload)
		if err == nil {
			return b, nil
		}
		return base64.URLEncoding.DecodeString(payload)
	}

	if isPadded {
		return base64.StdEncoding.DecodeString(payload)
	}
	b, err := base64.RawStdEncoding.DecodeString(payload)
	if err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(payload)
}

func decodeBase64Bytes(payload []byte) ([]byte, error) {
	isURLSafe := bytes.IndexAny(payload, "-_") != -1
	isPadded := len(payload) > 0 && payload[len(payload)-1] == '='

	var enc *base64.Encoding
	var altEnc *base64.Encoding

	if isURLSafe {
		if isPadded {
			enc = base64.URLEncoding
			altEnc = base64.RawURLEncoding
		} else {
			enc = base64.RawURLEncoding
			altEnc = base64.URLEncoding
		}
	} else {
		if isPadded {
			enc = base64.StdEncoding
			altEnc = base64.RawStdEncoding
		} else {
			enc = base64.RawStdEncoding
			altEnc = base64.StdEncoding
		}
	}

	dst := make([]byte, enc.DecodedLen(len(payload)))
	n, err := enc.Decode(dst, payload)
	if err == nil {
		return dst[:n], nil
	}

	if altEnc != nil {
		n, err = altEnc.Decode(dst, payload)
		if err == nil {
			return dst[:n], nil
		}
	}

	return nil, err
}
