#!/usr/bin/env python3
"""
rotate_keyset.py - Zero-downtime rotation for KMS-encrypted Google Tink Keysets.

Appends a new key to an existing keyset, sets it as PRIMARY, keeps old keys as ENABLED,
and re-encrypts the keyset under the KMS Master Key.

Usage:
    # AWS KMS:
    python rotate_keyset.py --kms-uri aws-kms://arn:aws:kms:... --in app-keyset.json --out app-keyset.json

    # GCP Cloud KMS:
    python rotate_keyset.py --kms-uri gcp-kms://projects/... --in app-keyset.json --out app-keyset.json

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
    parser = argparse.ArgumentParser(description="Rotate an existing KMS-encrypted Google Tink keyset")
    parser.add_argument(
        "--kms-uri",
        required=True,
        help="KMS Key URI (e.g. aws-kms://arn:aws:kms:... or gcp-kms://projects/...)"
    )
    parser.add_argument(
        "--in",
        dest="in_file",
        required=True,
        help="Path to existing encrypted keyset JSON file"
    )
    parser.add_argument(
        "--out",
        dest="out_file",
        default="",
        help="Destination path for rotated keyset (default: overwrites --in file)"
    )
    parser.add_argument(
        "--template",
        default="AES256_GCM",
        choices=["AES256_GCM", "XCHACHA20_POLY1305"],
        help="New key template algorithm (default: AES256_GCM)"
    )
    parser.add_argument(
        "--credentials",
        default="",
        help="Optional path to cloud credentials file"
    )

    args = parser.parse_args()
    out_file = args.out_file if args.out_file else args.in_file

    # 1. Register AEAD primitives in Tink
    aead.register()

    # 2. Bind KMS client
    if args.kms_uri.startswith("aws-kms://"):
        client = awskms.AwsKmsClient(args.kms_uri, args.credentials)
    elif args.kms_uri.startswith("gcp-kms://"):
        client = gcpkms.GcpKmsClient(args.kms_uri, args.credentials)
    else:
        print(f"Error: Unsupported KMS URI prefix: {args.kms_uri}", file=sys.stderr)
        sys.exit(1)

    try:
        master_aead = client.get_aead(args.kms_uri)
    except Exception as e:
        print(f"Error connecting to KMS: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Read and unwrap existing keyset
    try:
        with open(args.in_file, "r") as f:
            handle = tink.read_keyset_handle(tink.JsonKeysetReader(f.read()), master_aead)
    except Exception as e:
        print(f"Error reading and decrypting existing keyset {args.in_file}: {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Rotate keyset: Add new key, promote to PRIMARY, retain old keys as ENABLED
    try:
        manager = tink.KeysetManager(handle)
        template = getattr(aead.aead_key_templates, args.template)
        manager.rotate(template)
        rotated_handle = manager.get_keyset_handle()
    except Exception as e:
        print(f"Error rotating keyset: {e}", file=sys.stderr)
        sys.exit(1)

    # 5. Write re-encrypted keyset atomically to prevent file corruption and zero-byte truncation
    out_dir = os.path.dirname(os.path.abspath(out_file)) or "."
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=out_dir, delete=False, prefix=".keyset-rotate-tmp-") as f:
            tmp_path = f.name
            rotated_handle.write(tink.JsonKeysetWriter(f), master_aead)
            f.flush()
            os.fsync(f.fileno())

        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass  # Non-POSIX OS compatibility (e.g. Windows)

        os.replace(tmp_path, out_file)
        print(f"Successfully rotated keyset: {out_file}")
        print(f"New Primary Template: {args.template}")
        print(f"KMS Key:              {args.kms_uri}")
        print("Existing keys remain ENABLED for seamless historical decryptions.")
    except Exception as e:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        print(f"Error writing rotated keyset: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
