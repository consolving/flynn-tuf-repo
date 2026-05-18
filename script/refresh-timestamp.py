#!/usr/bin/env python3
"""
Refresh TUF timestamp.json and snapshot.json with new expiry dates.

Re-signs both files using ed25519 keys, incrementing version numbers
and setting expiry to 90 days from now.

Usage:
    # With key files (local development):
    python3 refresh-timestamp.py --repo-dir /path/to/flynn-tuf-repo

    # With environment variables (CI):
    export TUF_SNAPSHOT_SEED_HEX=<32-byte-hex-seed>
    export TUF_TIMESTAMP_SEED_HEX=<32-byte-hex-seed>
    python3 refresh-timestamp.py --repo-dir /path/to/flynn-tuf-repo

    # Custom expiry (days):
    python3 refresh-timestamp.py --repo-dir /path/to/flynn-tuf-repo --expiry-days 180
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone

try:
    from nacl.signing import SigningKey
except ImportError:
    print("ERROR: PyNaCl not installed. Run: pip install pynacl", file=sys.stderr)
    sys.exit(1)


def canonical_json(obj):
    """Produce canonical JSON (sorted keys, no whitespace, no trailing newline)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sign_metadata(signed_obj, key_id, signing_key):
    """Sign the 'signed' portion and return the full metadata dict."""
    signed_bytes = canonical_json(signed_obj).encode("utf-8")
    signature = signing_key.sign(signed_bytes).signature
    return {
        "signed": signed_obj,
        "signatures": [
            {
                "keyid": key_id,
                "method": "ed25519",
                "sig": signature.hex(),
            }
        ],
    }


def load_key_from_file(key_path):
    """Load ed25519 seed from go-tuf key file format."""
    with open(key_path) as f:
        key_data = json.load(f)
    private_hex = key_data["data"][0]["keyval"]["private"]
    # go-tuf stores seed (32 bytes) + public (32 bytes) = 64 bytes hex
    seed = bytes.fromhex(private_hex[:64])
    return seed


def load_key_from_env(env_var):
    """Load ed25519 seed from environment variable (hex-encoded 32-byte seed)."""
    hex_val = os.environ.get(env_var)
    if not hex_val:
        return None
    return bytes.fromhex(hex_val.strip())


def compute_key_id(public_key_hex):
    """Compute go-tuf key ID: SHA256 of canonical JSON key representation (without scheme field)."""
    key_obj = {"keytype": "ed25519", "keyval": {"public": public_key_hex}}
    return hashlib.sha256(canonical_json(key_obj).encode("utf-8")).hexdigest()


def file_hashes(data):
    """Compute SHA-256 and SHA-512 hashes of data bytes."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description="Refresh TUF timestamp and snapshot metadata")
    parser.add_argument("--repo-dir", required=True, help="Path to flynn-tuf-repo root")
    parser.add_argument("--expiry-days", type=int, default=90, help="Days until expiry (default: 90)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be done without writing")
    args = parser.parse_args()

    repo_dir = os.path.abspath(args.repo_dir)
    repository_dir = os.path.join(repo_dir, "repository")
    keys_dir = os.path.join(repo_dir, "keys")

    # Load current metadata
    with open(os.path.join(repository_dir, "snapshot.json")) as f:
        current_snapshot = json.load(f)
    with open(os.path.join(repository_dir, "timestamp.json")) as f:
        current_timestamp = json.load(f)

    snapshot_version = current_snapshot["signed"]["version"]
    timestamp_version = current_timestamp["signed"]["version"]

    print(f"Current snapshot version: {snapshot_version}, expires: {current_snapshot['signed']['expires']}")
    print(f"Current timestamp version: {timestamp_version}, expires: {current_timestamp['signed']['expires']}")

    # Load keys (prefer env vars, fall back to key files)
    snapshot_seed = load_key_from_env("TUF_SNAPSHOT_SEED_HEX")
    timestamp_seed = load_key_from_env("TUF_TIMESTAMP_SEED_HEX")

    if not snapshot_seed:
        key_file = os.path.join(keys_dir, "snapshot.json")
        if os.path.exists(key_file):
            snapshot_seed = load_key_from_file(key_file)
        else:
            print("ERROR: No snapshot key found (set TUF_SNAPSHOT_SEED_HEX or provide keys/snapshot.json)", file=sys.stderr)
            sys.exit(1)

    if not timestamp_seed:
        key_file = os.path.join(keys_dir, "timestamp.json")
        if os.path.exists(key_file):
            timestamp_seed = load_key_from_file(key_file)
        else:
            print("ERROR: No timestamp key found (set TUF_TIMESTAMP_SEED_HEX or provide keys/timestamp.json)", file=sys.stderr)
            sys.exit(1)

    snapshot_signing_key = SigningKey(snapshot_seed)
    timestamp_signing_key = SigningKey(timestamp_seed)

    # Verify key IDs match what's in current metadata
    snapshot_pub_hex = snapshot_signing_key.verify_key.encode().hex()
    timestamp_pub_hex = timestamp_signing_key.verify_key.encode().hex()
    snapshot_key_id = compute_key_id(snapshot_pub_hex)
    timestamp_key_id = compute_key_id(timestamp_pub_hex)

    expected_snapshot_key_id = current_snapshot["signatures"][0]["keyid"]
    expected_timestamp_key_id = current_timestamp["signatures"][0]["keyid"]

    if snapshot_key_id != expected_snapshot_key_id:
        print(f"ERROR: Snapshot key ID mismatch: computed {snapshot_key_id}, expected {expected_snapshot_key_id}", file=sys.stderr)
        sys.exit(1)
    if timestamp_key_id != expected_timestamp_key_id:
        print(f"ERROR: Timestamp key ID mismatch: computed {timestamp_key_id}, expected {expected_timestamp_key_id}", file=sys.stderr)
        sys.exit(1)

    print(f"Key IDs verified: snapshot={snapshot_key_id[:16]}..., timestamp={timestamp_key_id[:16]}...")

    # Compute new expiry
    new_expiry = datetime.now(timezone.utc) + timedelta(days=args.expiry_days)
    new_expiry_str = new_expiry.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Re-sign snapshot (increment version, update expiry, keep meta references)
    new_snapshot_version = snapshot_version + 1
    new_snapshot_signed = {
        "_type": "snapshot",
        "expires": new_expiry_str,
        "meta": current_snapshot["signed"]["meta"],
        "version": new_snapshot_version,
    }
    new_snapshot = sign_metadata(new_snapshot_signed, snapshot_key_id, snapshot_signing_key)
    new_snapshot_json = json.dumps(new_snapshot, indent="\t") + "\n"
    new_snapshot_bytes = new_snapshot_json.encode("utf-8")

    # Compute snapshot hash for timestamp (must match the exact bytes written to disk)
    snapshot_hashes = file_hashes(new_snapshot_bytes)

    # Re-sign timestamp (increment version, update expiry, update snapshot hash)
    new_timestamp_version = timestamp_version + 1
    # Keep existing meta references but update snapshot hash
    new_timestamp_meta = dict(current_timestamp["signed"]["meta"])
    new_timestamp_meta["snapshot.json"] = {
        "hashes": {"sha512": snapshot_hashes["sha512"]},
        "length": len(new_snapshot_bytes),
    }
    new_timestamp_signed = {
        "_type": "timestamp",
        "expires": new_expiry_str,
        "meta": new_timestamp_meta,
        "version": new_timestamp_version,
    }
    new_timestamp = sign_metadata(new_timestamp_signed, timestamp_key_id, timestamp_signing_key)
    new_timestamp_json = json.dumps(new_timestamp, indent="\t") + "\n"

    print(f"\nNew snapshot version: {new_snapshot_version}")
    print(f"New timestamp version: {new_timestamp_version}")
    print(f"New expiry: {new_expiry_str}")

    if args.dry_run:
        print("\n[DRY RUN] Would write:")
        print(f"  {os.path.join(repository_dir, 'snapshot.json')}")
        print(f"  {os.path.join(repository_dir, snapshot_hashes['sha512'] + '.snapshot.json')}")
        print(f"  {os.path.join(repository_dir, 'timestamp.json')}")
        return

    # Write snapshot (both canonical name and hash-prefixed for consistent snapshots)
    snapshot_path = os.path.join(repository_dir, "snapshot.json")
    with open(snapshot_path, "w") as f:
        f.write(new_snapshot_json)
    print(f"  Written: {snapshot_path}")

    # Write hash-prefixed snapshot (consistent snapshots format, full sha512 hash)
    hash_prefixed_path = os.path.join(repository_dir, f"{snapshot_hashes['sha512']}.snapshot.json")
    with open(hash_prefixed_path, "w") as f:
        f.write(new_snapshot_json)
    print(f"  Written: {hash_prefixed_path}")

    # Write timestamp
    timestamp_path = os.path.join(repository_dir, "timestamp.json")
    with open(timestamp_path, "w") as f:
        f.write(new_timestamp_json)
    print(f"  Written: {timestamp_path}")

    print("\nTUF metadata refreshed successfully.")


if __name__ == "__main__":
    main()
