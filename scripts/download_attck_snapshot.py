#!/usr/bin/env python3
"""Download and install the pinned MITRE Enterprise ATT&CK v18.1 snapshot.

The raw dataset is kept in ignored local data storage, never in the source tree
or Docker image. The pinned digest detects unexpected changes to the artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

from argusprowl.attck.knowledge_service import AttckKnowledgeService
from argusprowl.config.config_manager import ConfigManager
from argusprowl.constants.paths import ProjectPath

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

VERSION = "18.1"
URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "v18.1/enterprise-attack/enterprise-attack-18.1.json"
)
EXPECTED_SHA256 = "f857d8f78f2f0c0b7db321a711a39fba98546c1e3076a657684850c83d0962fb"
EXPECTED_BUNDLE_ID = "bundle--ffe1a478-536b-4e91-91b0-0ca0094a97d5"
MAX_BYTES = 80 * 1024 * 1024
LOCAL_SOURCE = ROOT / "data" / "attck" / "enterprise-attack-18.1.json"


def verify(data: bytes) -> dict:
    if len(data) > MAX_BYTES:
        raise ValueError(f"Dataset exceeds maximum accepted size ({MAX_BYTES} bytes).")
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(
            "ATT&CK v18.1 SHA-256 mismatch. The artifact was not imported. "
            f"Expected {EXPECTED_SHA256}; got {digest}. "
            "Check the source and pinned release before proceeding."
        )
    parsed = json.loads(data)
    if not isinstance(parsed, dict) or parsed.get("type") != "bundle":
        raise ValueError("Downloaded file is not a STIX bundle.")
    if parsed.get("id") != EXPECTED_BUNDLE_ID:
        raise ValueError("Unexpected STIX bundle ID; refusing import.")
    collections = [
        obj for obj in parsed.get("objects", [])
        if isinstance(obj, dict) and obj.get("type") == "x-mitre-collection"
    ]
    versions = {obj.get("x_mitre_version") for obj in collections}
    if versions != {VERSION}:
        raise ValueError(f"Expected Enterprise ATT&CK {VERSION}; found {versions!r}.")
    return parsed


def download() -> bytes:
    print(f"Downloading version-tagged Enterprise ATT&CK {VERSION}...")
    request = urllib.request.Request(
        URL,
        headers={"User-Agent": "ArgusProwl-Community/ATTCK-installer"},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        data = response.read(MAX_BYTES + 1)
    verify(data)
    LOCAL_SOURCE.parent.mkdir(parents=True, exist_ok=True)
    LOCAL_SOURCE.write_bytes(data)
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        default=str(ProjectPath.DEFAULT_CONFIG_FILE),
        help="YAML config path (default: project config/default.yaml)",
    )
    args = parser.parse_args()

    try:
        if LOCAL_SOURCE.exists():
            data = LOCAL_SOURCE.read_bytes()
            print(f"Using existing local download: {LOCAL_SOURCE}")
            verify(data)
        else:
            data = download()

        config = ConfigManager().load(args.config)
        attck_cfg = config.attck

        snapshot_path = Path(attck_cfg.snapshot_path)
        if not snapshot_path.is_absolute():
            snapshot_path = ProjectPath.ROOT / snapshot_path
        previous_path = (
            Path(attck_cfg.previous_snapshot_path)
            if attck_cfg.previous_snapshot_path
            else None
        )
        if previous_path is not None and not previous_path.is_absolute():
            previous_path = ProjectPath.ROOT / previous_path
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)

        service = AttckKnowledgeService(
            snapshot_path=snapshot_path,
            previous_snapshot_path=previous_path,
            enabled=True,
        )
        metadata = service.import_snapshot(data)

        if metadata.version != VERSION or metadata.integrity_hash != EXPECTED_SHA256:
            raise ValueError("Imported metadata did not match the pinned release.")

        print(f"Installed Enterprise ATT&CK {metadata.version}")
        print(f"Techniques: {metadata.technique_count:,}")
        print(f"Tactics: {metadata.tactic_count:,}")
        print(f"SHA-256: {metadata.integrity_hash}")
        print(f"Snapshot: {snapshot_path}")
        print("The dataset is stored locally and is excluded from Git.")
        return 0
    except Exception as exc:
        print(f"ATT&CK installation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
