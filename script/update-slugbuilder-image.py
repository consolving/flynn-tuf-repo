#!/usr/bin/env python3
"""
Publish a new slugbuilder-24 image (base + binaries + packages layers) into the
TUF repo: stages layer + layer json + image manifest, regenerates the versioned
images.json.gz / bootstrap-manifest.json.gz, bumps channels/stable, and re-signs
targets/snapshot/timestamp.

Usage:
    /usr/bin/python3 script/update-slugbuilder-image.py \
        --repo-dir /path/to/flynn-tuf-repo \
        --layer-squashfs /path/to/35d8c680...squashfs \
        --manifest /path/to/new-slugbuilder-manifest.json \
        --artifact-images /path/to/new-slugbuilder-artifact-images.json \
        --version v20260908.0 \
        --base-version v20260907.2
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

COMPONENT = "slugbuilder-24"


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def order_layer_json(layer_id, size):
    """Serialize a layer config in the flat-repo convention (export-tuf order)."""
    return json.dumps({
        "id": layer_id,
        "type": "application/vnd.flynn.image.squashfs.v1",
        "length": size,
        "hashes": {"sha512_256": layer_id},
    }, sort_keys=False, separators=(",", ":")).encode("utf-8")


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


def replace_artifacts(obj, new_artifact):
    """Replace any artifact object with meta.flynn.component == slugbuilder-24."""
    if isinstance(obj, dict):
        if obj.get("type") == "flynn" and obj.get("meta", {}).get("flynn.component") == COMPONENT:
            return json.loads(json.dumps(new_artifact))
        return {k: replace_artifacts(v, new_artifact) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [replace_artifacts(i, new_artifact) for i in obj]
    return obj


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", required=True)
    parser.add_argument("--layer-squashfs", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--artifact-images", required=True)
    parser.add_argument("--version", default="v" + datetime.now(timezone.utc).strftime("%Y%m%d.0"))
    parser.add_argument("--base-version", default="v20260907.2")
    parser.add_argument("--expiry-days", type=int, default=90)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    repo_dir = os.path.abspath(args.repo_dir)
    repository_dir = os.path.join(repo_dir, "repository")
    keys_dir = os.path.join(repo_dir, "keys")
    targets_dir = os.path.join(repository_dir, "targets")
    images_dir = os.path.join(targets_dir, "images")
    version_dir = os.path.join(targets_dir, args.version)
    base_version_dir = os.path.join(targets_dir, args.base_version)

    # --- layer ---
    new_layer_id = file_sha512_256(args.layer_squashfs)
    new_layer_size = os.path.getsize(args.layer_squashfs)
    new_layer_sha512 = file_sha512_from_path(args.layer_squashfs)
    print(f"Layer ID:    {new_layer_id}")
    print(f"Layer size:  {new_layer_size} ({new_layer_size / 1048576:.1f} MB)")

    # --- image manifest ---
    with open(args.manifest, "rb") as f:
        manifest_bytes = f.read()
    new_image_id = hashlib.new("sha512_256", manifest_bytes).hexdigest()
    new_image_sha512 = file_sha512(manifest_bytes)
    manifest_size = len(manifest_bytes)
    print(f"Image ID:    {new_image_id}")
    print(f"Image size:  {manifest_size}")

    # --- layer json ---
    layer_json_bytes = order_layer_json(new_layer_id, new_layer_size)
    layer_json_sha512 = file_sha512(layer_json_bytes)

    # --- artifact for images.json/bootstrap ---
    with open(args.artifact_images) as f:
        artifact_images = json.load(f)

    # --- locate current versioned images.json / bootstrap ---
    def find(base_dir, suffix):
        for f in os.listdir(base_dir):
            if f.endswith(suffix):
                return os.path.join(base_dir, f)
        return None

    src_images_gz = find(base_version_dir, ".images.json.gz")
    src_bootstrap_gz = find(base_version_dir, ".bootstrap-manifest.json.gz")
    if not src_images_gz or not src_bootstrap_gz:
        print(f"ERROR: missing versioned manifests in {base_version_dir}", file=sys.stderr)
        sys.exit(1)

    with gzip.open(src_images_gz, "rt") as f:
        images_data = json.load(f)
    images_data[COMPONENT] = json.loads(json.dumps(artifact_images))

    images_json_bytes = json.dumps(images_data, indent="  ").encode("utf-8")
    images_gz_bytes = gzip.compress(images_json_bytes)
    images_gz_sha512 = file_sha512(images_gz_bytes)

    with gzip.open(src_bootstrap_gz, "rt") as f:
        bootstrap_data = json.load(f)
    bootstrap_data = replace_artifacts(bootstrap_data, artifact_images)

    bootstrap_json_bytes = json.dumps(bootstrap_data, indent="  ").encode("utf-8")
    bootstrap_gz_bytes = gzip.compress(bootstrap_json_bytes)
    bootstrap_gz_sha512 = file_sha512(bootstrap_gz_bytes)

    # --- targets.json ---
    with open(os.path.join(repository_dir, "targets.json")) as f:
        current_targets = json.load(f)
    targets = current_targets["signed"]["targets"]
    targets_version = current_targets["signed"]["version"]

    # These keys are flat (matching the current repo layout)
    key_layer_sq = f"/{new_layer_id}.squashfs"
    key_layer_js = f"/{new_layer_id}.json"
    key_image_js = f"/images/{new_image_id}.json"
    key_images_gz = f"/{args.version}/images.json.gz"
    key_bootstrap_gz = f"/{args.version}/bootstrap-manifest.json.gz"

    add = {
        key_layer_sq: {"custom": {"version": args.version}, "hashes": {"sha512": new_layer_sha512}, "length": new_layer_size},
        key_layer_js: {"custom": {"version": args.version}, "hashes": {"sha512": layer_json_sha512}, "length": len(layer_json_bytes)},
        key_image_js: {"custom": {"version": args.version}, "hashes": {"sha512": new_image_sha512}, "length": manifest_size},
        key_images_gz: {"custom": {"version": args.version}, "hashes": {"sha512": images_gz_sha512}, "length": len(images_gz_bytes)},
        key_bootstrap_gz: {"custom": {"version": args.version}, "hashes": {"sha512": bootstrap_gz_sha512}, "length": len(bootstrap_gz_bytes)},
    }
    for k, v in add.items():
        targets[k] = v
        print(f"  target {k} ({v['length']} bytes)")

    # copy forward versioned binaries
    for key, val in list(targets.items()):
        if key.startswith(f"/{args.base_version}/") and "images.json" not in key and "bootstrap" not in key:
            new_key = key.replace(f"/{args.base_version}/", f"/{args.version}/")
            if new_key not in targets:
                targets[new_key] = dict(val)
                targets[new_key]["custom"] = {"version": args.version}
                print(f"  target {new_key} (copied forward)")

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

    # --- keys and signatures ---
    targets_seed = load_key_from_file(os.path.join(keys_dir, "targets.json"))
    snapshot_seed = load_key_from_file(os.path.join(keys_dir, "snapshot.json"))
    timestamp_seed = load_key_from_file(os.path.join(keys_dir, "timestamp.json"))

    targets_sk = SigningKey(targets_seed)
    snapshot_sk = SigningKey(snapshot_seed)
    timestamp_sk = SigningKey(timestamp_seed)

    targets_key_id = compute_key_id(targets_sk.verify_key.encode().hex())
    snapshot_key_id = compute_key_id(snapshot_sk.verify_key.encode().hex())
    timestamp_key_id = compute_key_id(timestamp_sk.verify_key.encode().hex())

    expected_targets_key_id = current_targets["signatures"][0]["keyid"]
    if targets_key_id != expected_targets_key_id:
        print(f"ERROR: Targets key ID mismatch: {targets_key_id} vs {expected_targets_key_id}", file=sys.stderr)
        sys.exit(1)

    new_targets = sign_metadata(new_targets_signed, targets_key_id, targets_sk)
    new_targets_json = json.dumps(new_targets, indent="\t") + "\n"
    new_targets_bytes = new_targets_json.encode("utf-8")
    new_targets_sha512 = file_sha512(new_targets_bytes)

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

    print(f"\nTargets v{targets_version} -> v{targets_version + 1} ({len(targets)} targets)")
    print(f"Snapshot v{snapshot_version} -> v{snapshot_version + 1}")
    print(f"Timestamp v{timestamp_version} -> v{timestamp_version + 1}")
    print(f"Expiry: {new_expiry_str}")

    if args.dry_run:
        print("\n[DRY RUN] Would write files. Exiting.")
        return

    # --- write files ---
    os.makedirs(version_dir, exist_ok=True)
    os.makedirs(images_dir, exist_ok=True)

    layer_sq_dst = os.path.join(targets_dir, f"{new_layer_sha512}.{new_layer_id}.squashfs")
    layer_js_dst = os.path.join(targets_dir, f"{layer_json_sha512}.{new_layer_id}.json")
    image_js_dst = os.path.join(images_dir, f"{new_image_sha512}.{new_image_id}.json")

    with open(layer_sq_dst, "wb") as f:
        with open(args.layer_squashfs, "rb") as src:
            f.write(src.read())
    with open(layer_js_dst, "wb") as f:
        f.write(layer_json_bytes)
    with open(image_js_dst, "wb") as f:
        f.write(manifest_bytes)

    images_gz_path = os.path.join(version_dir, f"{images_gz_sha512}.images.json.gz")
    with open(images_gz_path, "wb") as f:
        f.write(images_gz_bytes)
    bootstrap_gz_path = os.path.join(version_dir, f"{bootstrap_gz_sha512}.bootstrap-manifest.json.gz")
    with open(bootstrap_gz_path, "wb") as f:
        f.write(bootstrap_gz_bytes)

    for fname in os.listdir(base_version_dir):
        if "images.json" in fname or "bootstrap" in fname:
            continue
        src = os.path.join(base_version_dir, fname)
        dst = os.path.join(version_dir, fname)
        if not os.path.exists(dst):
            os.link(src, dst)

    channels_dir = os.path.join(targets_dir, "channels")
    os.makedirs(channels_dir, exist_ok=True)
    for f in os.listdir(channels_dir):
        if f.endswith(".stable"):
            os.remove(os.path.join(channels_dir, f))
    stable_sha512 = file_sha512(stable_content)
    with open(os.path.join(channels_dir, f"{stable_sha512}.stable"), "wb") as f:
        f.write(stable_content)
    with open(os.path.join(channels_dir, "stable"), "wb") as f:
        f.write(stable_content)

    targets_path = os.path.join(repository_dir, "targets.json")
    with open(targets_path, "w") as f:
        f.write(new_targets_json)
    for f in os.listdir(repository_dir):
        if f.endswith(".targets.json") and f != new_targets_sha512 + ".targets.json":
            os.remove(os.path.join(repository_dir, f))
    with open(os.path.join(repository_dir, f"{new_targets_sha512}.targets.json"), "w") as f:
        f.write(new_targets_json)

    for f in os.listdir(repository_dir):
        if f.endswith(".snapshot.json"):
            os.remove(os.path.join(repository_dir, f))
    with open(os.path.join(repository_dir, "snapshot.json"), "w") as f:
        f.write(new_snapshot_json)
    with open(os.path.join(repository_dir, f"{new_snapshot_sha512}.snapshot.json"), "w") as f:
        f.write(new_snapshot_json)

    with open(os.path.join(repository_dir, "timestamp.json"), "w") as f:
        f.write(new_timestamp_json)

    print(f"\nWrote:")
    print(f"  {layer_sq_dst}")
    print(f"  {layer_js_dst}")
    print(f"  {image_js_dst}")
    print(f"  {images_gz_path}")
    print(f"  {bootstrap_gz_path}")
    print(f"  channels/stable -> {args.version}")
    print(f"\nNew layer ID: {new_layer_id}")
    print(f"New image ID: {new_image_id}")
    print(f"\nNext steps:", file=sys.stderr)
    print(f"  1. Commit + push flynn-tuf-repo (files reachable via dl.consolving.net / consolving.github.io)", file=sys.stderr)
    print(f"  2. Create controller artifact from new-slugbuilder-artifact.json and set gitreceive SLUGBUILDER_24_IMAGE_ID", file=sys.stderr)


if __name__ == "__main__":
    main()