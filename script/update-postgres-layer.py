#!/usr/bin/env python3
"""
Update TUF metadata for new postgres packages layer.

Creates new layer JSON, new image manifest, and re-signs
targets.json, snapshot.json, and timestamp.json.

Usage:
    /usr/bin/python3 script/update-postgres-layer.py \
        --repo-dir /path/to/flynn-tuf-repo \
        --squashfs /path/to/postgres-packages.squashfs
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

# Old layer to replace
OLD_LAYER_ID = "a2c36fba1012311348d060085ec87b8cad8eefa2ac98a71f5504c066978f86a6"
OLD_IMAGE_ID = "e8eb225b12dc8f7882ce3391d4c6ebf75142bb6738eab6a41f472e4bee3bed37"


def canonical_json(obj):
    """Produce canonical JSON (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sign_metadata(signed_obj, key_id, signing_key):
    """Sign the 'signed' portion and return full metadata dict."""
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
    seed = bytes.fromhex(private_hex[:64])
    return seed


def compute_key_id(public_key_hex):
    """Compute go-tuf key ID (without scheme field)."""
    key_obj = {"keytype": "ed25519", "keyval": {"public": public_key_hex}}
    return hashlib.sha256(canonical_json(key_obj).encode("utf-8")).hexdigest()


def file_sha512(data):
    return hashlib.sha512(data).hexdigest()


def file_sha512_256(path):
    h = hashlib.new("sha512_256")
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1048576)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def file_sha512_from_path(path):
    h = hashlib.sha512()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1048576)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Update TUF metadata for new postgres packages layer")
    parser.add_argument("--repo-dir", required=True, help="Path to flynn-tuf-repo root")
    parser.add_argument("--squashfs", required=True, help="Path to new postgres-packages.squashfs")
    parser.add_argument("--version", default=None, help="Version tag (default: v{today}.0)")
    parser.add_argument("--expiry-days", type=int, default=90, help="Days until targets expiry")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be done")
    args = parser.parse_args()

    if args.version is None:
        args.version = datetime.now(timezone.utc).strftime("v%Y%m%d.0")

    repo_dir = os.path.abspath(args.repo_dir)
    repository_dir = os.path.join(repo_dir, "repository")
    keys_dir = os.path.join(repo_dir, "keys")
    layers_dir = os.path.join(repository_dir, "targets", "layers")
    images_dir = os.path.join(repository_dir, "targets", "images")

    # --- Compute new layer hash ---
    print(f"Computing sha512_256 of {args.squashfs}...")
    new_layer_id = file_sha512_256(args.squashfs)
    new_layer_size = os.path.getsize(args.squashfs)
    new_layer_sha512 = file_sha512_from_path(args.squashfs)
    print(f"  New layer ID: {new_layer_id}")
    print(f"  New layer size: {new_layer_size} ({new_layer_size / 1048576:.1f} MB)")

    # --- Create new layer JSON ---
    new_layer_json_obj = {
        "id": new_layer_id,
        "type": "application/vnd.flynn.image.squashfs.v1",
        "length": new_layer_size,
        "hashes": {"sha512_256": new_layer_id},
    }
    new_layer_json_bytes = canonical_json(new_layer_json_obj).encode("utf-8")
    new_layer_json_sha512 = file_sha512(new_layer_json_bytes)

    # Write layer JSON file (hash-prefixed filename)
    layer_json_filename = f"{new_layer_json_sha512}.{new_layer_id}.json"
    layer_json_path = os.path.join(layers_dir, layer_json_filename)
    print(f"\nNew layer JSON: {layer_json_filename}")

    # --- Create new image manifest ---
    # Read old image manifest to get structure
    old_image_filename = None
    for f in os.listdir(images_dir):
        if f.endswith(f".{OLD_IMAGE_ID}.json"):
            old_image_filename = f
            break

    if not old_image_filename:
        print(f"ERROR: Could not find image manifest for {OLD_IMAGE_ID}", file=sys.stderr)
        sys.exit(1)

    with open(os.path.join(images_dir, old_image_filename)) as f:
        old_image = json.load(f)

    # Replace old packages layer with new one in the image manifest
    new_image = json.loads(json.dumps(old_image))  # deep copy
    for rootfs in new_image["rootfs"]:
        for i, layer in enumerate(rootfs["layers"]):
            if layer["id"] == OLD_LAYER_ID:
                rootfs["layers"][i] = {
                    "hashes": {"sha512_256": new_layer_id},
                    "id": new_layer_id,
                    "length": new_layer_size,
                    "type": "application/vnd.flynn.image.squashfs.v1",
                }
                print(f"\n  Replaced layer {i} in image manifest:")
                print(f"    Old: {OLD_LAYER_ID} ({169418752} bytes)")
                print(f"    New: {new_layer_id} ({new_layer_size} bytes)")

    new_image_json_bytes = canonical_json(new_image).encode("utf-8")
    new_image_sha512 = file_sha512(new_image_json_bytes)

    # Compute new image ID (sha512_256 of the manifest content)
    new_image_id = hashlib.new("sha512_256", new_image_json_bytes).hexdigest()
    image_json_filename = f"{new_image_sha512}.{new_image_id}.json"
    image_json_path = os.path.join(images_dir, image_json_filename)
    print(f"\nNew image manifest: {image_json_filename}")
    print(f"  New image ID: {new_image_id}")

    # --- Load targets.json and update ---
    with open(os.path.join(repository_dir, "targets.json")) as f:
        current_targets = json.load(f)

    targets = current_targets["signed"]["targets"]
    targets_version = current_targets["signed"]["version"]

    # Add new layer .json entry
    targets[f"/layers/{new_layer_id}.json"] = {
        "custom": {"version": args.version},
        "hashes": {"sha512": new_layer_json_sha512},
        "length": len(new_layer_json_bytes),
    }

    # Add new layer .squashfs entry
    targets[f"/layers/{new_layer_id}.squashfs"] = {
        "custom": {"version": args.version},
        "hashes": {"sha512": new_layer_sha512},
        "length": new_layer_size,
    }

    # Add new image manifest entry
    targets[f"/images/{new_image_id}.json"] = {
        "custom": {"version": args.version},
        "hashes": {"sha512": new_image_sha512},
        "length": len(new_image_json_bytes),
    }

    # Keep old entries (don't remove them — other images might reference the old layer)

    new_expiry = datetime.now(timezone.utc) + timedelta(days=args.expiry_days)
    new_expiry_str = new_expiry.strftime("%Y-%m-%dT%H:%M:%SZ")

    new_targets_signed = {
        "_type": "targets",
        "expires": new_expiry_str,
        "targets": targets,
        "version": targets_version + 1,
    }

    print(f"\nTargets: version {targets_version} -> {targets_version + 1}")
    print(f"  New entries: 3 (layer .json, layer .squashfs, image .json)")
    print(f"  Expiry: {new_expiry_str}")

    # --- Load keys and sign ---
    print("\nLoading signing keys...")
    targets_seed = load_key_from_file(os.path.join(keys_dir, "targets.json"))
    snapshot_seed = load_key_from_file(os.path.join(keys_dir, "snapshot.json"))
    timestamp_seed = load_key_from_file(os.path.join(keys_dir, "timestamp.json"))

    targets_sk = SigningKey(targets_seed)
    snapshot_sk = SigningKey(snapshot_seed)
    timestamp_sk = SigningKey(timestamp_seed)

    targets_key_id = compute_key_id(targets_sk.verify_key.encode().hex())
    snapshot_key_id = compute_key_id(snapshot_sk.verify_key.encode().hex())
    timestamp_key_id = compute_key_id(timestamp_sk.verify_key.encode().hex())

    # Verify key IDs match
    expected_targets_key_id = current_targets["signatures"][0]["keyid"]
    if targets_key_id != expected_targets_key_id:
        print(f"ERROR: Targets key ID mismatch: {targets_key_id} vs {expected_targets_key_id}", file=sys.stderr)
        sys.exit(1)
    print(f"  Targets key: {targets_key_id[:16]}... OK")

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

    print(f"  Snapshot: version {snapshot_version} -> {snapshot_version + 1}")

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

    print(f"  Timestamp: version {timestamp_version} -> {timestamp_version + 1}")

    if args.dry_run:
        print("\n[DRY RUN] Would write the following files:")
        print(f"  {layer_json_path}")
        print(f"  {image_json_path}")
        print(f"  {os.path.join(repository_dir, 'targets.json')}")
        print(f"  {os.path.join(repository_dir, new_targets_sha512 + '.targets.json')}")
        print(f"  {os.path.join(repository_dir, 'snapshot.json')}")
        print(f"  {os.path.join(repository_dir, new_snapshot_sha512 + '.snapshot.json')}")
        print(f"  {os.path.join(repository_dir, 'timestamp.json')}")
        print(f"\nNew image ID: {new_image_id}")
        print(f"Old image ID: {OLD_IMAGE_ID}")
        print(f"\nRemember to:")
        print(f"  1. Upload {args.squashfs} to dl.consolving.net/tuf/repository/targets/layers/{new_layer_id}.squashfs")
        print(f"  2. Update bootstrap manifest / images.json with new image ID {new_image_id}")
        return

    # --- Write files ---
    print("\nWriting files...")

    # Layer JSON
    with open(layer_json_path, "wb") as f:
        f.write(new_layer_json_bytes)
    print(f"  {layer_json_path}")

    # Image manifest JSON
    with open(image_json_path, "wb") as f:
        f.write(new_image_json_bytes)
    print(f"  {image_json_path}")

    # targets.json (both canonical and hash-prefixed)
    targets_path = os.path.join(repository_dir, "targets.json")
    with open(targets_path, "w") as f:
        f.write(new_targets_json)
    print(f"  {targets_path}")

    # Remove old hash-prefixed targets.json
    for f in os.listdir(repository_dir):
        if f.endswith(".targets.json") and f != new_targets_sha512 + ".targets.json":
            old_path = os.path.join(repository_dir, f)
            os.remove(old_path)
            print(f"  Removed old: {f}")

    hash_targets_path = os.path.join(repository_dir, f"{new_targets_sha512}.targets.json")
    with open(hash_targets_path, "w") as f:
        f.write(new_targets_json)
    print(f"  {hash_targets_path}")

    # snapshot.json
    snapshot_path = os.path.join(repository_dir, "snapshot.json")
    with open(snapshot_path, "w") as f:
        f.write(new_snapshot_json)
    print(f"  {snapshot_path}")

    # Remove old hash-prefixed snapshot.json
    for f in os.listdir(repository_dir):
        if f.endswith(".snapshot.json") and f != new_snapshot_sha512 + ".snapshot.json":
            old_path = os.path.join(repository_dir, f)
            os.remove(old_path)
            print(f"  Removed old: {f}")

    hash_snapshot_path = os.path.join(repository_dir, f"{new_snapshot_sha512}.snapshot.json")
    with open(hash_snapshot_path, "w") as f:
        f.write(new_snapshot_json)
    print(f"  {hash_snapshot_path}")

    # timestamp.json
    timestamp_path = os.path.join(repository_dir, "timestamp.json")
    with open(timestamp_path, "w") as f:
        f.write(new_timestamp_json)
    print(f"  {timestamp_path}")

    print(f"\n{'='*60}")
    print(f"TUF metadata updated successfully!")
    print(f"{'='*60}")
    print(f"\nNew layer ID:  {new_layer_id}")
    print(f"New image ID:  {new_image_id}")
    print(f"Old image ID:  {OLD_IMAGE_ID}")
    print(f"\nNext steps:")
    print(f"  1. Upload squashfs to dl.consolving.net:")
    print(f"     scp {args.squashfs} dl.consolving.net:/path/to/tuf/repository/targets/layers/{new_layer_id}.squashfs")
    print(f"  2. Update references to old image ID -> new image ID:")
    print(f"     - bootstrap/manifest_template.json")
    print(f"     - Any images.json targets")
    print(f"  3. Commit and push flynn-tuf-repo")


if __name__ == "__main__":
    main()
