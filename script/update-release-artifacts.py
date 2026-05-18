#!/usr/bin/env python3
"""
Update images.json.gz and bootstrap-manifest.json.gz with new postgres image ID.

Must be run AFTER update-postgres-layer.py which creates the new image manifest.

Usage:
    /usr/bin/python3 script/update-release-artifacts.py \
        --repo-dir /path/to/flynn-tuf-repo \
        --old-image-id e8eb225b12dc8f7882ce3391d4c6ebf75142bb6738eab6a41f472e4bee3bed37 \
        --new-image-id 85f8c3f11e0d7def3c20009ac78ddc4048d44990e5c2a83be20d3f13c749845f
"""

import argparse
import gzip
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

NEW_LAYER_ID = "9f0b3c39731d65f192a48ee9dc0feceaa791a7da86cd131e01341ef1056a8b63"
NEW_LAYER_SIZE = 381657088
OLD_LAYER_ID = "a2c36fba1012311348d060085ec87b8cad8eefa2ac98a71f5504c066978f86a6"


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sign_metadata(signed_obj, key_id, signing_key):
    signed_bytes = canonical_json(signed_obj).encode("utf-8")
    signature = signing_key.sign(signed_bytes).signature
    return {
        "signed": signed_obj,
        "signatures": [{"keyid": key_id, "method": "ed25519", "sig": signature.hex()}],
    }


def load_key_from_file(key_path):
    with open(key_path) as f:
        key_data = json.load(f)
    private_hex = key_data["data"][0]["keyval"]["private"]
    return bytes.fromhex(private_hex[:64])


def compute_key_id(public_key_hex):
    key_obj = {"keytype": "ed25519", "keyval": {"public": public_key_hex}}
    return hashlib.sha256(canonical_json(key_obj).encode("utf-8")).hexdigest()


def file_sha512(data):
    return hashlib.sha512(data).hexdigest()


def update_postgres_refs(obj, old_image_id, new_image_id):
    """Recursively replace old image ID with new in any JSON structure."""
    if isinstance(obj, str):
        return obj.replace(old_image_id, new_image_id).replace(OLD_LAYER_ID, NEW_LAYER_ID)
    elif isinstance(obj, dict):
        new_dict = {}
        for k, v in obj.items():
            new_dict[k] = update_postgres_refs(v, old_image_id, new_image_id)
        # Fix layer length if this is the replaced layer
        if isinstance(new_dict.get("id"), str) and new_dict.get("id") == NEW_LAYER_ID:
            new_dict["length"] = NEW_LAYER_SIZE
        # Fix image size if this is postgres entry with updated hash
        return new_dict
    elif isinstance(obj, list):
        return [update_postgres_refs(item, old_image_id, new_image_id) for item in obj]
    elif isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    return obj


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", required=True)
    parser.add_argument("--old-image-id", required=True)
    parser.add_argument("--new-image-id", required=True)
    parser.add_argument("--version", default="v20260515.0")
    parser.add_argument("--expiry-days", type=int, default=90)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    repo_dir = os.path.abspath(args.repo_dir)
    repository_dir = os.path.join(repo_dir, "repository")
    keys_dir = os.path.join(repo_dir, "keys")
    version_dir = os.path.join(repository_dir, "targets", args.version)

    # Find current images.json.gz and bootstrap-manifest.json.gz
    images_gz = None
    bootstrap_gz = None
    for f in os.listdir(os.path.join(repository_dir, "targets", "v20260505.0")):
        if f.endswith(".images.json.gz"):
            images_gz = os.path.join(repository_dir, "targets", "v20260505.0", f)
        elif f.endswith(".bootstrap-manifest.json.gz"):
            bootstrap_gz = os.path.join(repository_dir, "targets", "v20260505.0", f)

    if not images_gz or not bootstrap_gz:
        print("ERROR: Could not find images.json.gz or bootstrap-manifest.json.gz", file=sys.stderr)
        sys.exit(1)

    print(f"Source images.json.gz: {os.path.basename(images_gz)}")
    print(f"Source bootstrap-manifest.json.gz: {os.path.basename(bootstrap_gz)}")

    # Read and update images.json
    with gzip.open(images_gz, "rt") as f:
        images_data = json.load(f)

    images_data = update_postgres_refs(images_data, args.old_image_id, args.new_image_id)

    # Recompute postgres entry size (size of the new image manifest JSON)
    # Read new image manifest to get its canonical size
    images_dir = os.path.join(repository_dir, "targets", "images")
    new_manifest_file = None
    for f in os.listdir(images_dir):
        if f.endswith(f".{args.new_image_id}.json"):
            new_manifest_file = os.path.join(images_dir, f)
            break

    if new_manifest_file:
        new_manifest_size = os.path.getsize(new_manifest_file)
        if "postgres" in images_data:
            images_data["postgres"]["size"] = new_manifest_size
            print(f"  Updated postgres image size to {new_manifest_size}")

    # Serialize and gzip images.json
    images_json_bytes = json.dumps(images_data, indent="  ").encode("utf-8")
    images_gz_bytes = gzip.compress(images_json_bytes)
    images_gz_sha512 = file_sha512(images_gz_bytes)

    print(f"\nNew images.json.gz: {len(images_gz_bytes)} bytes, sha512={images_gz_sha512[:32]}...")

    # Read and update bootstrap-manifest.json
    with gzip.open(bootstrap_gz, "rt") as f:
        bootstrap_data = json.load(f)

    bootstrap_data = update_postgres_refs(bootstrap_data, args.old_image_id, args.new_image_id)

    bootstrap_json_bytes = json.dumps(bootstrap_data, indent="  ").encode("utf-8")
    bootstrap_gz_bytes = gzip.compress(bootstrap_json_bytes)
    bootstrap_gz_sha512 = file_sha512(bootstrap_gz_bytes)

    print(f"New bootstrap-manifest.json.gz: {len(bootstrap_gz_bytes)} bytes, sha512={bootstrap_gz_sha512[:32]}...")

    # Create new version directory
    os.makedirs(version_dir, exist_ok=True)

    # Also need to copy over non-postgres artifacts from v20260505.0
    # (flynn-host.gz, flynn-linux-amd64.gz, flynn-init.gz)

    # Load and update targets.json
    with open(os.path.join(repository_dir, "targets.json")) as f:
        current_targets = json.load(f)

    targets = current_targets["signed"]["targets"]
    targets_version = current_targets["signed"]["version"]

    # Add new images.json.gz entry
    images_target_path = f"/{args.version}/images.json.gz"
    targets[images_target_path] = {
        "custom": {"version": args.version},
        "hashes": {"sha512": images_gz_sha512},
        "length": len(images_gz_bytes),
    }

    # Add new bootstrap-manifest.json.gz entry
    bootstrap_target_path = f"/{args.version}/bootstrap-manifest.json.gz"
    targets[bootstrap_target_path] = {
        "custom": {"version": args.version},
        "hashes": {"sha512": bootstrap_gz_sha512},
        "length": len(bootstrap_gz_bytes),
    }

    # Copy forward other version entries (flynn-host.gz, flynn-linux-amd64.gz, flynn-init.gz)
    # from v20260505.0
    for key, val in list(targets.items()):
        if key.startswith("/v20260505.0/") and key not in (
            "/v20260505.0/images.json.gz",
            "/v20260505.0/bootstrap-manifest.json.gz",
        ):
            new_key = key.replace("/v20260505.0/", f"/{args.version}/")
            if new_key not in targets:
                targets[new_key] = dict(val)
                targets[new_key]["custom"] = {"version": args.version}

    # Update channels/stable to new version
    stable_content = args.version.encode("utf-8")
    targets["/channels/stable"] = {
        "custom": {"version": args.version},
        "hashes": {"sha512": file_sha512(stable_content)},
        "length": len(stable_content),
    }

    new_expiry = datetime.now(timezone.utc) + timedelta(days=args.expiry_days)
    new_expiry_str = new_expiry.strftime("%Y-%m-%dT%H:%M:%SZ")

    new_targets_signed = {
        "_type": "targets",
        "expires": new_expiry_str,
        "targets": targets,
        "version": targets_version + 1,
    }

    print(f"\nTargets: version {targets_version} -> {targets_version + 1}")

    # Load keys
    print("Loading signing keys...")
    targets_seed = load_key_from_file(os.path.join(keys_dir, "targets.json"))
    snapshot_seed = load_key_from_file(os.path.join(keys_dir, "snapshot.json"))
    timestamp_seed = load_key_from_file(os.path.join(keys_dir, "timestamp.json"))

    targets_sk = SigningKey(targets_seed)
    snapshot_sk = SigningKey(snapshot_seed)
    timestamp_sk = SigningKey(timestamp_seed)

    targets_key_id = compute_key_id(targets_sk.verify_key.encode().hex())
    snapshot_key_id = compute_key_id(snapshot_sk.verify_key.encode().hex())
    timestamp_key_id = compute_key_id(timestamp_sk.verify_key.encode().hex())

    # Sign targets
    new_targets = sign_metadata(new_targets_signed, targets_key_id, targets_sk)
    new_targets_json = json.dumps(new_targets, indent="\t") + "\n"
    new_targets_bytes = new_targets_json.encode("utf-8")
    new_targets_sha512 = file_sha512(new_targets_bytes)

    # Sign snapshot
    with open(os.path.join(repository_dir, "snapshot.json")) as f:
        current_snapshot = json.load(f)

    snapshot_version = current_snapshot["signed"]["version"]
    snapshot_meta = dict(current_snapshot["signed"]["meta"])
    snapshot_meta["targets.json"] = {
        "hashes": {"sha512": new_targets_sha512},
        "length": len(new_targets_bytes),
    }

    new_snapshot_signed = {
        "_type": "snapshot",
        "expires": new_expiry_str,
        "meta": snapshot_meta,
        "version": snapshot_version + 1,
    }
    new_snapshot = sign_metadata(new_snapshot_signed, snapshot_key_id, snapshot_sk)
    new_snapshot_json = json.dumps(new_snapshot, indent="\t") + "\n"
    new_snapshot_bytes = new_snapshot_json.encode("utf-8")
    new_snapshot_sha512 = file_sha512(new_snapshot_bytes)

    # Sign timestamp
    with open(os.path.join(repository_dir, "timestamp.json")) as f:
        current_timestamp = json.load(f)

    timestamp_version = current_timestamp["signed"]["version"]
    timestamp_meta = dict(current_timestamp["signed"]["meta"])
    timestamp_meta["snapshot.json"] = {
        "hashes": {"sha512": new_snapshot_sha512},
        "length": len(new_snapshot_bytes),
    }

    new_timestamp_signed = {
        "_type": "timestamp",
        "expires": new_expiry_str,
        "meta": timestamp_meta,
        "version": timestamp_version + 1,
    }
    new_timestamp = sign_metadata(new_timestamp_signed, timestamp_key_id, timestamp_sk)
    new_timestamp_json = json.dumps(new_timestamp, indent="\t") + "\n"

    print(f"  Snapshot: version {snapshot_version} -> {snapshot_version + 1}")
    print(f"  Timestamp: version {timestamp_version} -> {timestamp_version + 1}")

    if args.dry_run:
        print("\n[DRY RUN] Would write files. Exiting.")
        return

    # Write files
    print("\nWriting files...")

    # images.json.gz
    images_gz_path = os.path.join(version_dir, f"{images_gz_sha512}.images.json.gz")
    with open(images_gz_path, "wb") as f:
        f.write(images_gz_bytes)
    print(f"  {images_gz_path}")

    # bootstrap-manifest.json.gz
    bootstrap_gz_path = os.path.join(version_dir, f"{bootstrap_gz_sha512}.bootstrap-manifest.json.gz")
    with open(bootstrap_gz_path, "wb") as f:
        f.write(bootstrap_gz_bytes)
    print(f"  {bootstrap_gz_path}")

    # Copy forward other artifacts from v20260505.0 (symlink or copy)
    src_version_dir = os.path.join(repository_dir, "targets", "v20260505.0")
    for f in os.listdir(src_version_dir):
        if "images.json" in f or "bootstrap-manifest" in f:
            continue
        src = os.path.join(src_version_dir, f)
        dst = os.path.join(version_dir, f)
        if not os.path.exists(dst):
            os.link(src, dst)  # hard link to save space
            print(f"  Linked: {f}")

    # Write channels/stable
    stable_path = os.path.join(repository_dir, "targets", "channels")
    os.makedirs(stable_path, exist_ok=True)
    stable_file = os.path.join(stable_path, "stable")
    # Find hash-prefixed stable file and update it
    channels_dir = os.path.join(repository_dir, "targets", "channels")
    for f in os.listdir(channels_dir):
        if f.endswith(".stable"):
            os.remove(os.path.join(channels_dir, f))
    stable_sha512 = file_sha512(stable_content)
    with open(os.path.join(channels_dir, f"{stable_sha512}.stable"), "wb") as f:
        f.write(stable_content)
    with open(os.path.join(channels_dir, "stable"), "wb") as f:
        f.write(stable_content)
    print(f"  Updated channels/stable -> {args.version}")

    # targets.json
    targets_path = os.path.join(repository_dir, "targets.json")
    with open(targets_path, "w") as f:
        f.write(new_targets_json)

    # Remove old hash-prefixed targets.json
    for f in os.listdir(repository_dir):
        if f.endswith(".targets.json"):
            os.remove(os.path.join(repository_dir, f))

    hash_targets_path = os.path.join(repository_dir, f"{new_targets_sha512}.targets.json")
    with open(hash_targets_path, "w") as f:
        f.write(new_targets_json)
    print(f"  targets.json v{targets_version + 1}")

    # snapshot.json
    for f in os.listdir(repository_dir):
        if f.endswith(".snapshot.json"):
            os.remove(os.path.join(repository_dir, f))

    with open(os.path.join(repository_dir, "snapshot.json"), "w") as f:
        f.write(new_snapshot_json)
    with open(os.path.join(repository_dir, f"{new_snapshot_sha512}.snapshot.json"), "w") as f:
        f.write(new_snapshot_json)
    print(f"  snapshot.json v{snapshot_version + 1}")

    # timestamp.json
    with open(os.path.join(repository_dir, "timestamp.json"), "w") as f:
        f.write(new_timestamp_json)
    print(f"  timestamp.json v{timestamp_version + 1}")

    print(f"\nRelease {args.version} created successfully!")
    print(f"Postgres image: {args.old_image_id[:16]}... -> {args.new_image_id[:16]}...")


if __name__ == "__main__":
    main()
