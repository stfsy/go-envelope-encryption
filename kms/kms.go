package kms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/tink-crypto/tink-go-awskms/v2/integration/awskms"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/testing/fakekms"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var (
	// ErrInvalidURI is returned when a KMS Key URI is malformed or unsupported.
	ErrInvalidURI = errors.New("kms: invalid or unsupported key URI")
	// ErrKMSInitialization is returned when a KMS client fails to initialize.
	ErrKMSInitialization = errors.New("kms: failed to initialize KMS client")
)

// NewAWSKMSEncrypter initializes a tink.AEAD primitive using AWS KMS.
// keyARN must be a valid AWS KMS key ARN (e.g., "aws-kms://arn:aws:kms:us-east-1:123456789012:key/...")
// or standard ARN starting with "arn:aws:kms:".
func NewAWSKMSEncrypter(keyARN string, opts ...awskms.ClientOption) (tink.AEAD, error) {
	if keyARN == "" {
		return nil, fmt.Errorf("%w: key ARN cannot be empty", ErrInvalidURI)
	}

	uri := keyARN
	if !strings.HasPrefix(uri, "aws-kms://") {
		uri = "aws-kms://" + keyARN
	}

	client, err := awskms.NewClientWithOptions(uri, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKMSInitialization, err)
	}

	aead, err := client.GetAEAD(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get AEAD for key: %v", ErrKMSInitialization, err)
	}

	return aead, nil
}

// NewGCPKMSEncrypter initializes a tink.AEAD primitive using Google Cloud KMS.
// keyURI must be a valid GCP KMS key URI:
// "gcp-kms://projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}"
// or standard resource name starting with "projects/".
func NewGCPKMSEncrypter(ctx context.Context, keyURI string, opts ...gcpkms.Option) (tink.AEAD, error) {
	if keyURI == "" {
		return nil, fmt.Errorf("%w: key URI cannot be empty", ErrInvalidURI)
	}

	uri := keyURI
	if !strings.HasPrefix(uri, "gcp-kms://") {
		uri = "gcp-kms://" + keyURI
	}

	client, err := gcpkms.NewClient(ctx, uri, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKMSInitialization, err)
	}

	aead, err := client.GetAEAD(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get AEAD for key: %v", ErrKMSInitialization, err)
	}

	return aead, nil
}

// NewMockKMSEncrypter initializes an in-memory mock KMS AEAD for unit tests and local development.
// If keyURI is empty, a new random fake KMS key URI is generated automatically.
// Returns the AEAD primitive and the resulting key URI.
func NewMockKMSEncrypter(keyURI string) (tink.AEAD, string, error) {
	uri := keyURI
	if uri == "" {
		generatedURI, err := fakekms.NewKeyURI()
		if err != nil {
			return nil, "", fmt.Errorf("%w: failed to generate mock key URI: %v", ErrKMSInitialization, err)
		}
		uri = generatedURI
	} else if !strings.HasPrefix(uri, "fake-kms://") {
		uri = "fake-kms://" + uri
	}

	aead, err := fakekms.NewAEAD(uri)
	if err != nil {
		return nil, "", fmt.Errorf("%w: failed to get AEAD for mock key: %v", ErrKMSInitialization, err)
	}

	return aead, uri, nil
}
