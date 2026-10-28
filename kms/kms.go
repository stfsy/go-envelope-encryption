package kms

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/testing/fakekms"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var (
	// ErrInvalidURI is returned when a KMS Key URI is malformed or unsupported.
	ErrInvalidURI = errors.New("kms: invalid or unsupported key URI")
	// ErrKMSInitialization is returned when a KMS client fails to initialize.
	ErrKMSInitialization = errors.New("kms: failed to initialize KMS client")

	awsARNRegionRe = regexp.MustCompile(`^aws-kms://arn:aws[a-zA-Z0-9-_]*:kms:([a-z0-9-]+):`)
)

// AWSKMSClient defines the AWS KMS API operations required for envelope encryption.
type AWSKMSClient interface {
	Encrypt(ctx context.Context, params *awskms.EncryptInput, optFns ...func(*awskms.Options)) (*awskms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *awskms.DecryptInput, optFns ...func(*awskms.Options)) (*awskms.DecryptOutput, error)
}

type awsOptions struct {
	cfgOpts []func(*config.LoadOptions) error
	client  AWSKMSClient
}

// AWSOption configures the AWS KMS encrypter.
type AWSOption func(*awsOptions)

// WithAWSConfigOptions appends custom AWS SDK v2 config load options.
func WithAWSConfigOptions(opts ...func(*config.LoadOptions) error) AWSOption {
	return func(o *awsOptions) {
		o.cfgOpts = append(o.cfgOpts, opts...)
	}
}

// WithAWSKMSClient injects a pre-configured AWS KMS client (or mock).
func WithAWSKMSClient(client AWSKMSClient) AWSOption {
	return func(o *awsOptions) {
		o.client = client
	}
}

// NewAWSKMSEncrypter initializes a tink.AEAD (and tink.AEADWithContext) primitive using AWS SDK for Go v2.
// keyARN must be a valid AWS KMS key ARN (e.g., "aws-kms://arn:aws:kms:us-east-1:123456789012:key/...")
// or standard ARN starting with "arn:aws:kms:".
func NewAWSKMSEncrypter(ctx context.Context, keyARN string, opts ...AWSOption) (tink.AEAD, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context cannot be nil", ErrKMSInitialization)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	keyARN = strings.TrimSpace(keyARN)
	if keyARN == "" {
		return nil, fmt.Errorf("%w: key ARN cannot be empty", ErrInvalidURI)
	}

	uri := keyARN
	if !strings.HasPrefix(strings.ToLower(uri), "aws-kms://") {
		uri = "aws-kms://" + keyARN
	}

	matches := awsARNRegionRe.FindStringSubmatch(uri)
	if len(matches) != 2 {
		return nil, fmt.Errorf("%w: could not extract AWS region from ARN %q", ErrInvalidURI, keyARN)
	}
	region := matches[1]

	var o awsOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	client := o.client
	if client == nil {
		loadOpts := append([]func(*config.LoadOptions) error{config.WithRegion(region)}, o.cfgOpts...)
		cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrKMSInitialization, err)
		}
		client = awskms.NewFromConfig(cfg)
	}

	rawARN := uri[len("aws-kms://"):]
	return &awsAEAD{
		keyID:  rawARN,
		client: client,
	}, nil
}

type awsAEAD struct {
	keyID  string
	client AWSKMSClient
}

var (
	_ tink.AEAD            = (*awsAEAD)(nil)
	_ tink.AEADWithContext = (*awsAEAD)(nil)
)

func (a *awsAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return a.EncryptWithContext(context.Background(), plaintext, associatedData)
}

func (a *awsAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return a.DecryptWithContext(context.Background(), ciphertext, associatedData)
}

func (a *awsAEAD) EncryptWithContext(ctx context.Context, plaintext, associatedData []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("kms: context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req := &awskms.EncryptInput{
		KeyId:     aws.String(a.keyID),
		Plaintext: plaintext,
	}
	if len(associatedData) > 0 {
		req.EncryptionContext = map[string]string{
			"associatedData": hex.EncodeToString(associatedData),
		}
	}
	resp, err := a.client.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.CiphertextBlob, nil
}

func (a *awsAEAD) DecryptWithContext(ctx context.Context, ciphertext, associatedData []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("kms: context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req := &awskms.DecryptInput{
		KeyId:          aws.String(a.keyID),
		CiphertextBlob: ciphertext,
	}
	if len(associatedData) > 0 {
		req.EncryptionContext = map[string]string{
			"associatedData": hex.EncodeToString(associatedData),
		}
	}
	resp, err := a.client.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

// NewGCPKMSEncrypter initializes a tink.AEAD primitive using Google Cloud KMS.
// keyURI must be a valid GCP KMS key URI:
// "gcp-kms://projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}"
// or standard resource name starting with "projects/".
// The returned AEAD implements io.Closer to release underlying gRPC connection resources.
func NewGCPKMSEncrypter(ctx context.Context, keyURI string, opts ...gcpkms.Option) (tink.AEAD, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context cannot be nil", ErrKMSInitialization)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	keyURI = strings.TrimSpace(keyURI)
	if keyURI == "" {
		return nil, fmt.Errorf("%w: key URI cannot be empty", ErrInvalidURI)
	}

	uri := keyURI
	if !strings.HasPrefix(uri, "gcp-kms://") {
		if !strings.HasPrefix(uri, "projects/") {
			return nil, fmt.Errorf("%w: expected gcp-kms:// URI or projects/ resource name", ErrInvalidURI)
		}
		uri = "gcp-kms://" + uri
	} else {
		rest := strings.TrimPrefix(uri, "gcp-kms://")
		if !strings.HasPrefix(rest, "projects/") {
			return nil, fmt.Errorf("%w: expected projects/ resource name after gcp-kms:// prefix", ErrInvalidURI)
		}
	}

	client, err := gcpkms.NewClient(ctx, uri, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKMSInitialization, err)
	}

	aead, err := client.GetAEAD(uri)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("%w: failed to get AEAD for key: %w", ErrKMSInitialization, err)
	}

	return &gcpClosableAEAD{
		AEAD:   aead,
		client: client,
	}, nil
}

type gcpClosableAEAD struct {
	tink.AEAD
	client *gcpkms.Client
}

var (
	_ tink.AEAD            = (*gcpClosableAEAD)(nil)
	_ tink.AEADWithContext = (*gcpClosableAEAD)(nil)
	_ io.Closer            = (*gcpClosableAEAD)(nil)
)

func (g *gcpClosableAEAD) EncryptWithContext(ctx context.Context, plaintext, associatedData []byte) ([]byte, error) {
	if pwc, ok := g.AEAD.(tink.AEADWithContext); ok {
		return pwc.EncryptWithContext(ctx, plaintext, associatedData)
	}
	return g.AEAD.Encrypt(plaintext, associatedData)
}

func (g *gcpClosableAEAD) DecryptWithContext(ctx context.Context, ciphertext, associatedData []byte) ([]byte, error) {
	if pwc, ok := g.AEAD.(tink.AEADWithContext); ok {
		return pwc.DecryptWithContext(ctx, ciphertext, associatedData)
	}
	return g.AEAD.Decrypt(ciphertext, associatedData)
}

func (g *gcpClosableAEAD) Close() error {
	if g.client != nil {
		return g.client.Close()
	}
	return nil
}

// NewMockKMSEncrypter initializes an in-memory mock KMS AEAD for unit tests and local development.
//
// WARNING: DO NOT USE THIS IN PRODUCTION. The underlying fake KMS embeds raw key material directly
// inside the URI and provides no cryptographic security for production workloads.
//
// If keyURI is empty, a new random fake KMS key URI is generated automatically.
// Returns the AEAD primitive and the resulting key URI.
func NewMockKMSEncrypter(keyURI string) (tink.AEAD, string, error) {
	uri := keyURI
	if uri == "" {
		generatedURI, err := fakekms.NewKeyURI()
		if err != nil {
			return nil, "", fmt.Errorf("%w: failed to generate mock key URI: %w", ErrKMSInitialization, err)
		}
		uri = generatedURI
	} else if !strings.HasPrefix(uri, "fake-kms://") {
		uri = "fake-kms://" + uri
	}

	aead, err := fakekms.NewAEAD(uri)
	if err != nil {
		return nil, "", fmt.Errorf("%w: failed to get AEAD for mock key: %w", ErrKMSInitialization, err)
	}

	return aead, uri, nil
}
