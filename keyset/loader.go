package keyset

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/tink-crypto/tink-go/v2/aead"
	tinkkeyset "github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	// MaxKeysetJSONSize is the maximum allowable size for a serialized keyset JSON (4 MiB).
	MaxKeysetJSONSize = 4 * 1024 * 1024
)

var (
	// AES256GCM is the recommended Tink AEAD template for 256-bit AES-GCM keys.
	AES256GCM = aead.AES256GCMKeyTemplate()
	// XChaCha20Poly1305 is the recommended Tink AEAD template for 256-bit XChaCha20-Poly1305 keys.
	XChaCha20Poly1305 = aead.XChaCha20Poly1305KeyTemplate()
)

var (
	// ErrInvalidKeyset is returned when keyset deserialization or unwrap fails.
	ErrInvalidKeyset = errors.New("keyset: invalid or corrupted keyset")
	// ErrNilMasterKey is returned when master KMS key is nil.
	ErrNilMasterKey = errors.New("keyset: master KMS key cannot be nil")
	// ErrEmptyPath is returned when a secret file path is empty.
	ErrEmptyPath = errors.New("keyset: secret file path cannot be empty")
	// ErrUnsupportedKeyType is returned when a non-AEAD key template is passed for keyset generation or rotation.
	ErrUnsupportedKeyType = errors.New("keyset: unsupported AEAD key template type")
	// ErrKeysetTooLarge is returned when a keyset reader exceeds MaxKeysetJSONSize.
	ErrKeysetTooLarge = errors.New("keyset: keyset exceeds maximum allowable size")
)

var supportedAEADTypes = map[string]bool{
	"type.googleapis.com/google.crypto.tink.AesGcmKey":            true,
	"type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key": true,
	"type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey":    true,
	"type.googleapis.com/google.crypto.tink.AesGcmSivKey":         true,
	"type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key":  true,
}

// ValidateAEADTemplate verifies that the provided key template is a supported AEAD algorithm.
func ValidateAEADTemplate(template *tinkpb.KeyTemplate) error {
	if template == nil {
		return nil
	}
	if !supportedAEADTypes[template.GetTypeUrl()] {
		return fmt.Errorf("%w: %q", ErrUnsupportedKeyType, template.GetTypeUrl())
	}
	return nil
}

func validateAEADTemplate(template *tinkpb.KeyTemplate) error {
	return ValidateAEADTemplate(template)
}

// LoadEncryptedKeyset reads a JSON-serialized keyset from r and unwraps it using masterKey.
// A bounded reader is used to prevent memory exhaustion if r is oversized or infinite.
func LoadEncryptedKeyset(r io.Reader, masterKey tink.AEAD) (*tinkkeyset.Handle, error) {
	if masterKey == nil {
		return nil, ErrNilMasterKey
	}
	if r == nil {
		return nil, fmt.Errorf("%w: reader cannot be nil", ErrInvalidKeyset)
	}

	buf, err := io.ReadAll(io.LimitReader(r, MaxKeysetJSONSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read keyset: %v", ErrInvalidKeyset, err)
	}
	if len(buf) > MaxKeysetJSONSize {
		return nil, ErrKeysetTooLarge
	}

	reader := tinkkeyset.NewJSONReader(bytes.NewReader(buf))
	handle, err := tinkkeyset.Read(reader, masterKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read and unwrap keyset: %v", ErrInvalidKeyset, err)
	}
	return handle, nil
}

// LoadMountedSecret opens a secret file mounted at path and unwraps the keyset using masterKey.
func LoadMountedSecret(path string, masterKey tink.AEAD) (*tinkkeyset.Handle, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keyset: failed to open mounted secret %q: %w", path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	return LoadEncryptedKeyset(f, masterKey)
}

// GenerateEncryptedKeyset creates a new keyset with template and writes the KMS-encrypted JSON to w.
func GenerateEncryptedKeyset(w io.Writer, masterKey tink.AEAD, template *tinkpb.KeyTemplate) error {
	if masterKey == nil {
		return ErrNilMasterKey
	}
	if w == nil {
		return fmt.Errorf("%w: writer cannot be nil", ErrInvalidKeyset)
	}
	if template == nil {
		template = AES256GCM
	}
	if err := validateAEADTemplate(template); err != nil {
		return err
	}

	handle, err := tinkkeyset.NewHandle(template)
	if err != nil {
		return fmt.Errorf("keyset: failed to generate new keyset handle: %w", err)
	}

	writer := tinkkeyset.NewJSONWriter(w)
	if err := handle.Write(writer, masterKey); err != nil {
		return fmt.Errorf("keyset: failed to serialize and encrypt keyset: %w", err)
	}
	return nil
}

// RotateEncryptedKeyset unwraps an existing encrypted keyset from r, appends a new key with newTemplate,
// marks the new key as PRIMARY, and writes the updated re-encrypted keyset to w.
func RotateEncryptedKeyset(r io.Reader, w io.Writer, masterKey tink.AEAD, newTemplate *tinkpb.KeyTemplate) error {
	if masterKey == nil {
		return ErrNilMasterKey
	}
	if r == nil {
		return fmt.Errorf("%w: reader cannot be nil", ErrInvalidKeyset)
	}
	if w == nil {
		return fmt.Errorf("%w: writer cannot be nil", ErrInvalidKeyset)
	}
	if newTemplate == nil {
		newTemplate = AES256GCM
	}
	if err := ValidateAEADTemplate(newTemplate); err != nil {
		return err
	}

	handle, err := LoadEncryptedKeyset(r, masterKey)
	if err != nil {
		return err
	}

	manager := tinkkeyset.NewManagerFromHandle(handle)
	keyID, err := manager.Add(newTemplate)
	if err != nil {
		return fmt.Errorf("keyset: failed to add new key to manager: %w", err)
	}

	if err := manager.SetPrimary(keyID); err != nil {
		return fmt.Errorf("keyset: failed to set new key %d as primary: %w", keyID, err)
	}

	rotatedHandle, err := manager.Handle()
	if err != nil {
		return fmt.Errorf("keyset: failed to obtain updated handle: %w", err)
	}

	writer := tinkkeyset.NewJSONWriter(w)
	if err := rotatedHandle.Write(writer, masterKey); err != nil {
		return fmt.Errorf("keyset: failed to write rotated keyset: %w", err)
	}
	return nil
}
