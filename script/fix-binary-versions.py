#!/usr/bin/env python3
"""
Fix the v20260811.0 release: the flynn-host/flynn-init/flynn-linux-amd64
binaries were built without the --version flag, embedding "dev" as the
version string instead of "v20260811.0". This causes `flynn-host download`
to loop forever (download binary -> re-exec -> version mismatch -> repeat).

This script replaces the binary targets in the existing v20260811.0 TUF
release with correctly-versioned rebuilds, re-signs targets/snapshot/timestamp,
without bumping the release version tag itself (same v20260811.0).

Usage:
    python3 fix-binary-versions.py --repo-dir /path/to/flynn-tuf-repo \
        --build-dir /tmp/flynn-build-fix/bin --version v20260811.0
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


def gzip_file(src_path):
    with open(src_path, "rb") as f:
        data = f.read()
    return gzip.compress(data, compresslevel=9)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", required=True)
    parser.add_argument("--build-dir", required=True, help="dir containing rebuilt flynn-host, flynn-init, flynn-linux-amd64")
    parser.add_argument("--version", default="v20260811.0")
    parser.add_argument("--expiry-days", type=int, default=90)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    repo_dir = os.path.abspath(args.repo_dir)
    repository_dir = os.path.join(repo_dir, "repository")
    keys_dir = os.path.join(repo_dir, "keys")
    version_dir = os.path.join(repository_dir, "targets", args.version)

    # Build new gzipped binaries
    print("Gzipping rebuilt binaries...")
    new_host_gz = gzip_file(os.path.join(args.build_dir, "flynn-host"))
    new_init_gz = gzip_file(os.path.join(args.build_dir, "flynn-init"))
    new_linux_amd64_gz = gzip_file(os.path.join(args.build_dir, "flynn-linux-amd64"))

    host_sha512 = file_sha512(new_host_gz)
    init_sha512 = file_sha512(new_init_gz)
    linux_amd64_sha512 = file_sha512(new_linux_amd64_gz)

    print(f"  flynn-host.gz: {len(new_host_gz)} bytes, sha512={host_sha512[:32]}...")
    print(f"  flynn-init.gz: {len(new_init_gz)} bytes, sha512={init_sha512[:32]}...")
    print(f"  flynn-linux-amd64.gz: {len(new_linux_amd64_gz)} bytes, sha512={linux_amd64_sha512[:32]}...")

    # Load current targets.json
    with open(os.path.join(repository_dir, "targets.json")) as f:
        current_targets = json.load(f)
    targets = current_targets["signed"]["targets"]
    targets_version = current_targets["signed"]["version"]

    old_entries = {}
    target_paths = {
        "/flynn-host.gz": (new_host_gz, host_sha512),
        "/flynn-linux-amd64.gz": (new_linux_amd64_gz, linux_amd64_sha512),
        f"/{args.version}/flynn-host.gz": (new_host_gz, host_sha512),
        f"/{args.version}/flynn-init.gz": (new_init_gz, init_sha512),
        f"/{args.version}/flynn-linux-amd64.gz": (new_linux_amd64_gz, linux_amd64_sha512),
    }
    for path, (data, sha512) in target_paths.items():
        old_entries[path] = targets.get(path)
        targets[path] = {
            "custom": {"version": args.version},
            "hashes": {"sha512": sha512},
            "length": len(data),
        }
        print(f"  Updated target {path}: length {old_entries[path]['length'] if old_entries[path] else '?'} -> {len(data)}")

    new_expiry = datetime.now(timezone.utc) + timedelta(days=args.expiry_days)
    new_expiry_str = new_expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
    new_targets_signed = {
        "_type": "targets",
        "expires": new_expiry_str,
        "targets": targets,
        "version": targets_version + 1,
    }
    print(f"\nTargets: version {targets_version} -> {targets_version + 1}")

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

    # Sanity check: computed key IDs must match root.json's declared role keyids
    with open(os.path.join(repository_dir, "root.json")) as f:
        root_signed = json.load(f)["signed"]
    for role, kid in (("targets", targets_key_id), ("snapshot", snapshot_key_id), ("timestamp", timestamp_key_id)):
        expected = root_signed["roles"][role]["keyids"]
        if kid not in expected:
            print(f"ERROR: computed {role} key id {kid} not in root.json's {expected}", file=sys.stderr)
            sys.exit(1)
        print(f"  {role} key id OK: {kid}")

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

    print(f"  Snapshot: version {snapshot_version} -> {snapshot_version + 1}")
    print(f"  Timestamp: version {timestamp_version} -> {timestamp_version + 1}")

    if args.dry_run:
        print("\n[DRY RUN] Would write files. Exiting.")
        return

    print("\nWriting files...")
    os.makedirs(version_dir, exist_ok=True)

    # Write new hashed binary files (top-level + versioned)
    with open(os.path.join(repository_dir, f"{host_sha512}.flynn-host.gz"), "wb") as f:
        f.write(new_host_gz)
    with open(os.path.join(repository_dir, f"{linux_amd64_sha512}.flynn-linux-amd64.gz"), "wb") as f:
        f.write(new_linux_amd64_gz)
    with open(os.path.join(version_dir, f"{host_sha512}.flynn-host.gz"), "wb") as f:
        f.write(new_host_gz)
    with open(os.path.join(version_dir, f"{init_sha512}.flynn-init.gz"), "wb") as f:
        f.write(new_init_gz)
    with open(os.path.join(version_dir, f"{linux_amd64_sha512}.flynn-linux-amd64.gz"), "wb") as f:
        f.write(new_linux_amd64_gz)
    print("  Wrote new hashed binary files")

    # Remove old hash-prefixed binary files that are no longer referenced
    for path, old in old_entries.items():
        if not old:
            continue
        old_hash = old["hashes"]["sha512"]
        base = os.path.basename(path)
        for d in (repository_dir, version_dir):
            old_file = os.path.join(d, f"{old_hash}.{base}")
            if os.path.exists(old_file) and old_hash not in (host_sha512, init_sha512, linux_amd64_sha512):
                os.remove(old_file)
                print(f"  Removed stale {old_file}")

    # targets.json
    targets_path = os.path.join(repository_dir, "targets.json")
    with open(targets_path, "w") as f:
        f.write(new_targets_json)
    for f_name in os.listdir(repository_dir):
        if f_name.endswith(".targets.json"):
            os.remove(os.path.join(repository_dir, f_name))
    with open(os.path.join(repository_dir, f"{new_targets_sha512}.targets.json"), "w") as f:
        f.write(new_targets_json)
    print(f"  targets.json v{targets_version + 1}")

    # snapshot.json
    for f_name in os.listdir(repository_dir):
        if f_name.endswith(".snapshot.json"):
            os.remove(os.path.join(repository_dir, f_name))
    with open(os.path.join(repository_dir, "snapshot.json"), "w") as f:
        f.write(new_snapshot_json)
    with open(os.path.join(repository_dir, f"{new_snapshot_sha512}.snapshot.json"), "w") as f:
        f.write(new_snapshot_json)
    print(f"  snapshot.json v{snapshot_version + 1}")

    # timestamp.json (not consistent-snapshotted, always at fixed path)
    with open(os.path.join(repository_dir, "timestamp.json"), "w") as f:
        f.write(new_timestamp_json)
    print(f"  timestamp.json v{timestamp_version + 1}")

    print(f"\nRelease {args.version} binary versions fixed successfully!")


if __name__ == "__main__":
    main()
