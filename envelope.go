package envelope

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stfsy/go-envelope-encryption/keyset"
	"github.com/tink-crypto/tink-go/v2/aead"
	tinkkeyset "github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var (
	// ErrNilPrimitive is returned when attempting to initialize a Client with a nil AEAD primitive.
	ErrNilPrimitive = errors.New("envelope: AEAD primitive cannot be nil")
	// ErrNilPlaintext is returned when plaintext to encrypt is nil.
	ErrNilPlaintext = errors.New("envelope: plaintext cannot be nil")
	// ErrDecryptionFailed is returned when authentication or decryption fails.
	ErrDecryptionFailed = errors.New("envelope: decryption failed")
	// ErrClientClosed is returned when an operation is performed on a closed Client.
	ErrClientClosed = errors.New("envelope: client is closed")
	// ErrInvalidAAD is returned when more than one AAD slice is passed to an operation.
	ErrInvalidAAD = errors.New("envelope: at most one AAD slice may be provided")
)

type options struct {
	autoReloadInterval time.Duration
	secretPath         string
	kmsMaster          tink.AEAD
	onReloadError      func(error)
	reloader           func() (tink.AEAD, error)
}

// Option configures Client behavior.
type Option func(*options)

// WithAutoReload configures the client to watch the mounted secret file and hot-reload.
func WithAutoReload(interval time.Duration) Option {
	return func(o *options) {
		o.autoReloadInterval = interval
	}
}

// WithReloadErrorHandler registers a callback for background keyset reload errors.
func WithReloadErrorHandler(fn func(error)) Option {
	return func(o *options) {
		o.onReloadError = fn
	}
}

func withReloader(fn func() (tink.AEAD, error)) Option {
	return func(o *options) {
		o.reloader = fn
	}
}

func withSecretMount(secretPath string, kmsKey tink.AEAD) Option {
	return func(o *options) {
		o.secretPath = secretPath
		o.kmsMaster = kmsKey
	}
}

// Client provides envelope encryption and decryption with modular wire formatting,
// automatic keyset rotation, and optional secret mount hot-reloading.
type Client struct {
	primitive    atomic.Pointer[tink.AEAD]
	closed       atomic.Bool
	stopReloader chan struct{}
	reloader     func() (tink.AEAD, error)
	reloadMu     sync.Mutex
}

// New creates a Client wrapping an existing tink.AEAD primitive.
func New(primitive tink.AEAD, opts ...Option) (*Client, error) {
	if primitive == nil {
		return nil, ErrNilPrimitive
	}

	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	c := &Client{
		stopReloader: make(chan struct{}),
		reloader:     o.reloader,
	}
	c.primitive.Store(&primitive)

	if o.autoReloadInterval > 0 && (o.secretPath != "" || o.reloader != nil) {
		c.startAutoReloader(o.secretPath, o.kmsMaster, o.autoReloadInterval, o.onReloadError)
	}

	return c, nil
}

// NewFromKeysetHandle creates a Client from a Tink KeysetHandle.
func NewFromKeysetHandle(handle *tinkkeyset.Handle, opts ...Option) (*Client, error) {
	if handle == nil {
		return nil, errors.New("envelope: keyset handle cannot be nil")
	}
	primitive, err := aead.New(handle)
	if err != nil {
		return nil, fmt.Errorf("envelope: failed to instantiate AEAD from keyset: %w", err)
	}
	return New(primitive, opts...)
}

// NewFromEncryptedKeyset loads and unwraps a KMS-encrypted keyset JSON from an io.Reader.
func NewFromEncryptedKeyset(r io.Reader, kmsKey tink.AEAD, opts ...Option) (*Client, error) {
	handle, err := keyset.LoadEncryptedKeyset(r, kmsKey)
	if err != nil {
		return nil, err
	}
	return NewFromKeysetHandle(handle, opts...)
}

// NewFromMountedSecret loads and unwraps a KMS-encrypted keyset JSON from a mounted file path.
// If WithAutoReload is passed, the file will be periodically checked for updates and hot-reloaded.
func NewFromMountedSecret(ctx context.Context, secretPath string, kmsKey tink.AEAD, opts ...Option) (*Client, error) {
	loadFn := func() (tink.AEAD, error) {
		handle, err := keyset.LoadMountedSecret(secretPath, kmsKey)
		if err != nil {
			return nil, err
		}
		primitive, err := aead.New(handle)
		if err != nil {
			return nil, fmt.Errorf("envelope: failed to instantiate AEAD: %w", err)
		}
		return primitive, nil
	}

	primitive, err := loadFn()
	if err != nil {
		return nil, err
	}

	clientOpts := append([]Option{
		withReloader(loadFn),
		withSecretMount(secretPath, kmsKey),
	}, opts...)

	return New(primitive, clientOpts...)
}

// buildLocalEnvelopeAEAD wraps kekAEAD in an envelope AEAD producing ephemeral DEKs with dekTemplate.
func buildLocalEnvelopeAEAD(kekAEAD tink.AEAD, dekTemplate *tinkpb.KeyTemplate) (tink.AEAD, error) {
	if kekAEAD == nil {
		return nil, errors.New("envelope: kekAEAD cannot be nil")
	}
	if dekTemplate == nil {
		dekTemplate = keyset.AES256GCM
	}
	if err := keyset.ValidateAEADTemplate(dekTemplate); err != nil {
		return nil, err
	}
	if pwc, ok := kekAEAD.(tink.AEADWithContext); ok {
		primitive, err := aead.NewKMSEnvelopeAEADWithContext(dekTemplate, pwc)
		if err == nil {
			return &aeadWithContextAdapter{p: primitive}, nil
		}
	}
	return aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD), nil
}

// NewLocalEnvelope initializes a 2-tier local envelope client using an in-memory KEK Keyset.
// Ephemeral DEKs are generated per payload in memory without network calls to KMS.
func NewLocalEnvelope(kekAEAD tink.AEAD, dekTemplate *tinkpb.KeyTemplate, opts ...Option) (*Client, error) {
	primitive, err := buildLocalEnvelopeAEAD(kekAEAD, dekTemplate)
	if err != nil {
		return nil, err
	}
	return New(primitive, opts...)
}

// NewLocalEnvelopeFromMountedSecret initializes a 2-tier local envelope client where the KEK keyset
// is mounted from secretPath and unwrapped using kmsKey. Ephemeral DEKs are generated per payload using dekTemplate.
// If WithAutoReload is passed, secretPath is periodically monitored for rotated KEK keysets,
// preserving the 2-tier envelope wrapping across reloads without cryptographic drift.
func NewLocalEnvelopeFromMountedSecret(ctx context.Context, secretPath string, kmsKey tink.AEAD, dekTemplate *tinkpb.KeyTemplate, opts ...Option) (*Client, error) {
	if dekTemplate == nil {
		dekTemplate = keyset.AES256GCM
	}

	loadFn := func() (tink.AEAD, error) {
		handle, err := keyset.LoadMountedSecret(secretPath, kmsKey)
		if err != nil {
			return nil, err
		}
		kekAEAD, err := aead.New(handle)
		if err != nil {
			return nil, fmt.Errorf("envelope: failed to instantiate KEK AEAD: %w", err)
		}
		return buildLocalEnvelopeAEAD(kekAEAD, dekTemplate)
	}

	primitive, err := loadFn()
	if err != nil {
		return nil, err
	}

	clientOpts := append([]Option{
		withReloader(loadFn),
		withSecretMount(secretPath, kmsKey),
	}, opts...)

	return New(primitive, clientOpts...)
}

// NewDirectKMSEnvelope initializes a 2-tier direct cloud envelope client.
// Every Encrypt/Decrypt call wraps/unwraps the ephemeral DEK directly via remote cloud KMS.
func NewDirectKMSEnvelope(kmsAEAD tink.AEAD, dekTemplate *tinkpb.KeyTemplate, opts ...Option) (*Client, error) {
	if kmsAEAD == nil {
		return nil, errors.New("envelope: kmsAEAD cannot be nil")
	}
	if dekTemplate == nil {
		dekTemplate = keyset.AES256GCM
	}
	if err := keyset.ValidateAEADTemplate(dekTemplate); err != nil {
		return nil, err
	}
	if pwc, ok := kmsAEAD.(tink.AEADWithContext); ok {
		primitive, err := aead.NewKMSEnvelopeAEADWithContext(dekTemplate, pwc)
		if err == nil {
			return New(&aeadWithContextAdapter{p: primitive}, opts...)
		}
	}
	primitive := aead.NewKMSEnvelopeAEAD2(dekTemplate, kmsAEAD)
	return New(primitive, opts...)
}

var bgCtx = context.Background()

type aeadWithContextAdapter struct {
	p tink.AEADWithContext
}

func (a *aeadWithContextAdapter) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return a.p.EncryptWithContext(bgCtx, plaintext, associatedData)
}

func (a *aeadWithContextAdapter) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return a.p.DecryptWithContext(bgCtx, ciphertext, associatedData)
}

func (a *aeadWithContextAdapter) EncryptWithContext(ctx context.Context, plaintext, associatedData []byte) ([]byte, error) {
	return a.p.EncryptWithContext(ctx, plaintext, associatedData)
}

func (a *aeadWithContextAdapter) DecryptWithContext(ctx context.Context, ciphertext, associatedData []byte) ([]byte, error) {
	return a.p.DecryptWithContext(ctx, ciphertext, associatedData)
}

func (c *Client) getPrimitive() (tink.AEAD, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}
	p := c.primitive.Load()
	if p == nil || *p == nil {
		return nil, ErrNilPrimitive
	}
	return *p, nil
}

// Encrypt encrypts plaintext with optional AAD and returns a modular wire string:
// $tink$<base64_standard>
func (c *Client) Encrypt(ctx context.Context, plaintext []byte, aad ...[]byte) (string, error) {
	raw, err := c.EncryptBytes(ctx, plaintext, aad...)
	if err != nil {
		return "", err
	}
	if len(Prefix)+base64.StdEncoding.EncodedLen(len(raw)) > MaxCiphertextLen {
		return "", ErrCiphertextTooLarge
	}
	return FormatWire(raw), nil
}

// Decrypt decodes a $tink$<base64> string and decrypts the underlying payload.
func (c *Client) Decrypt(ctx context.Context, ciphertext string, aad ...[]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(aad) > 1 {
		return nil, ErrInvalidAAD
	}
	raw, err := ParseWire(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	return c.DecryptBytes(ctx, raw, aad...)
}

// DecryptWireBytes decodes a $tink$<base64> byte slice and decrypts the underlying payload.
// This is the zero-string-allocation fast-path for callers receiving byte slices from HTTP request
// bodies or database drivers.
func (c *Client) DecryptWireBytes(ctx context.Context, wire []byte, aad ...[]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(aad) > 1 {
		return nil, ErrInvalidAAD
	}
	raw, err := ParseWireBytes(wire)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	return c.DecryptBytes(ctx, raw, aad...)
}

func extractAAD(aad [][]byte) ([]byte, error) {
	if len(aad) > 1 {
		return nil, ErrInvalidAAD
	}
	if len(aad) == 1 {
		return aad[0], nil
	}
	return nil, nil
}

// EncryptBytes encrypts plaintext with optional AAD, returning raw envelope bytes.
func (c *Client) EncryptBytes(ctx context.Context, plaintext []byte, aad ...[]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if plaintext == nil {
		return nil, ErrNilPlaintext
	}
	extraAAD, err := extractAAD(aad)
	if err != nil {
		return nil, err
	}
	p, err := c.getPrimitive()
	if err != nil {
		return nil, err
	}

	if pwc, ok := p.(tink.AEADWithContext); ok {
		return pwc.EncryptWithContext(ctx, plaintext, extraAAD)
	}
	return p.Encrypt(plaintext, extraAAD)
}

// DecryptBytes decrypts raw envelope bytes with optional AAD.
func (c *Client) DecryptBytes(ctx context.Context, ciphertext []byte, aad ...[]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, ErrEmptyCiphertext
	}
	extraAAD, err := extractAAD(aad)
	if err != nil {
		return nil, err
	}
	p, err := c.getPrimitive()
	if err != nil {
		return nil, err
	}

	var plaintext []byte
	if pwc, ok := p.(tink.AEADWithContext); ok {
		plaintext, err = pwc.DecryptWithContext(ctx, ciphertext, extraAAD)
	} else {
		plaintext, err = p.Decrypt(ciphertext, extraAAD)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	return plaintext, nil
}

// Reload re-reads and unwraps the mounted secret from path, atomically updating the in-memory primitive.
// If a custom reloader was configured (e.g. for local envelope wrapping), it is invoked to preserve
// the exact envelope wrapping structure.
func (c *Client) Reload(secretPath string, kmsKey tink.AEAD) error {
	if c.closed.Load() {
		return ErrClientClosed
	}

	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()

	if c.closed.Load() {
		return ErrClientClosed
	}

	var newPrimitive tink.AEAD
	var err error

	if c.reloader != nil {
		newPrimitive, err = c.reloader()
	} else {
		handle, loadErr := keyset.LoadMountedSecret(secretPath, kmsKey)
		if loadErr != nil {
			return loadErr
		}
		newPrimitive, err = aead.New(handle)
		if err != nil {
			return fmt.Errorf("envelope: failed to instantiate reloaded AEAD: %w", err)
		}
	}

	if err != nil {
		return err
	}

	c.primitive.Store(&newPrimitive)
	return nil
}

func (c *Client) startAutoReloader(path string, kmsKey tink.AEAD, interval time.Duration, onErr func(error)) {
	ticker := time.NewTicker(interval)
	var lastModTime time.Time
	var lastSize int64

	if fi, err := os.Stat(path); err == nil {
		lastModTime = fi.ModTime()
		lastSize = fi.Size()
	}

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-c.stopReloader:
				return
			case <-ticker.C:
				fi, err := os.Stat(path)
				if err != nil {
					// In Kubernetes / Cloud Run, secret volume updates atomically swap symlinks (..data_tmp -> ..data).
					// A stat right during the swap can transiently return os.ErrNotExist.
					// We retry once after a short delay before calling onErr.
					time.Sleep(50 * time.Millisecond)
					fi, err = os.Stat(path)
					if err != nil {
						if onErr != nil {
							onErr(err)
						}
						continue
					}
				}

				if !fi.ModTime().Equal(lastModTime) || fi.Size() != lastSize {
					if err := c.Reload(path, kmsKey); err != nil {
						if onErr != nil {
							onErr(err)
						}
					} else {
						lastModTime = fi.ModTime()
						lastSize = fi.Size()
					}
				}
			}
		}
	}()
}

// Close gracefully closes the client, terminating any background hot-reloader goroutines.
func (c *Client) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.stopReloader)
		c.primitive.Store(nil)
	}
	return nil
}
