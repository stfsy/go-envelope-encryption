#!/usr/bin/env python3
"""
create_keyset.py - Generate a new KMS-encrypted Google Tink Keyset JSON file.

Usage:
    # AWS KMS:
    python create_keyset.py --kms-uri aws-kms://arn:aws:kms:us-east-1:123456789012:key/my-key-id --out app-keyset.json

    # GCP Cloud KMS:
    python create_keyset.py --kms-uri gcp-kms://projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key --out app-keyset.json

Requirements:
    pip install tink
    pip install boto3              # If using AWS KMS
    pip install google-cloud-kms   # If using GCP KMS
"""

import argparse
import os
import sys
import tempfile
import tink
from tink import aead
from tink.integration import awskms, gcpkms


def main():
    parser = argparse.ArgumentParser(description="Create a new KMS-encrypted Google Tink keyset")
    parser.add_argument(
        "--kms-uri",
        required=True,
        help="KMS Key URI (e.g. aws-kms://arn:aws:kms:... or gcp-kms://projects/...)"
    )
    parser.add_argument(
        "--out",
        default="app-keyset.json",
        help="Destination path for encrypted keyset JSON file (default: app-keyset.json)"
    )
    parser.add_argument(
        "--template",
        default="AES256_GCM",
        choices=["AES256_GCM", "XCHACHA20_POLY1305"],
        help="Key template algorithm (default: AES256_GCM)"
    )
    parser.add_argument(
        "--credentials",
        default="",
        help="Optional path to cloud credentials file"
    )

    args = parser.parse_args()

    # 1. Register AEAD primitives in Tink
    aead.register()

    # 2. Bind KMS client
    if args.kms_uri.startswith("aws-kms://"):
        client = awskms.AwsKmsClient(args.kms_uri, args.credentials)
    elif args.kms_uri.startswith("gcp-kms://"):
        client = gcpkms.GcpKmsClient(args.kms_uri, args.credentials)
    else:
        print(f"Error: Unsupported KMS URI prefix: {args.kms_uri}", file=sys.stderr)
        print("Expected URI starting with 'aws-kms://' or 'gcp-kms://'", file=sys.stderr)
        sys.exit(1)

    try:
        master_aead = client.get_aead(args.kms_uri)
    except Exception as e:
        print(f"Error connecting to KMS: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Generate a fresh Tink keyset
    template = getattr(aead.aead_key_templates, args.template)
    keyset_handle = tink.new_keyset_handle(template)

    # 4. Serialize and encrypt keyset under KMS root key using atomic write and restricted permissions
    out_dir = os.path.dirname(os.path.abspath(args.out)) or "."
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=out_dir, delete=False, prefix=".keyset-tmp-") as f:
            tmp_path = f.name
            keyset_handle.write(tink.JsonKeysetWriter(f), master_aead)
            f.flush()
            os.fsync(f.fileno())

        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass  # Non-POSIX OS compatibility (e.g. Windows)

        os.replace(tmp_path, args.out)
        print(f"Successfully generated KMS-encrypted keyset: {args.out}")
        print(f"Template: {args.template}")
        print(f"KMS Key:  {args.kms_uri}")
    except Exception as e:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        print(f"Error writing keyset file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
