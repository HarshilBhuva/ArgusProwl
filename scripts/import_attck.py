#!/usr/bin/env python3
"""Download and import an ATT&CK STIX bundle snapshot.

This script:
1. Downloads the MITRE ATT&CK STIX bundle for a specified version
2. Validates the bundle against the knowledge service's security bounds
3. Imports the snapshot into the configured snapshot path

Usage:
    python scripts/import_attck.py [--version VERSION] [--stix-file PATH] [--config PATH]
"""

import argparse
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import urllib.request

from argusprowl.attck.knowledge_service import AttckKnowledgeService
from argusprowl.config.config_manager import ConfigManager
from argusprowl.constants.paths import ProjectPath


def download_stix_bundle(url: str) -> bytes:
    """Download STIX bundle from URL."""
    print(f"Downloading from: {url}")
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    print(f"Downloaded {len(data):,} bytes")
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Import an ATT&CK STIX bundle snapshot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download latest version and import
  python import_attck.py --version 14.1

  # Import from local file
  python import_attck.py --stix-file /path/to/attck.json

  # Import from custom URL
  python import_attck.py --url https://example.com/attck.json
        """,
    )
    parser.add_argument(
        "--version",
        type=str,
        help="ATT&CK version to download (e.g., 14.0, 14.1, 15.1)",
    )
    parser.add_argument(
        "--stix-file",
        type=str,
        help="Local STIX JSON file to import",
    )
    parser.add_argument(
        "--url",
        type=str,
        help="URL to download STIX JSON from",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=str(ProjectPath.DEFAULT_CONFIG_FILE),
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Custom output path for the snapshot (overrides config)",
    )

    args = parser.parse_args()

    # Determine STIX data source
    if args.version:
        stix_url = f"https://attack.mitre.org/stix/versions/{args.version}/stix-bundle.json"
        source_desc = f"ATT&CK version {args.version}"
        data = download_stix_bundle(stix_url)
    elif args.stix_file:
        data = Path(args.stix_file).read_bytes()
        source_desc = f"local file: {args.stix_file}"
    elif args.url:
        data = download_stix_bundle(args.url)
        source_desc = f"URL: {args.url}"
    else:
        parser.error("Must specify --version, --stix-file, or --url")
        return 1

    # Load config
    config = ConfigManager().load(args.config)
    attck_cfg = config.attck

    # Determine snapshot path
    snapshot_path = Path(args.output) if args.output else Path(attck_cfg.snapshot_path)
    previous_path = (
        Path(attck_cfg.previous_snapshot_path) if attck_cfg.previous_snapshot_path else None
    )

    print(f"\nImporting ATT&CK snapshot to: {snapshot_path}")
    print(f"Snapshot size: {len(data):,} bytes ({len(data) / 1024 / 1024:.2f} MB)")

    # Import the snapshot
    knowledge_service = AttckKnowledgeService(
        snapshot_path=snapshot_path,
        previous_snapshot_path=previous_path,
        enabled=attck_cfg.enabled,
    )

    try:
        metadata = knowledge_service.import_snapshot(data)

        print(f"\n✓ Successfully imported ATT&CK snapshot from {source_desc}")
        print(f"  Version:           {metadata.version}")
        print(f"  Techniques:        {metadata.technique_count:,}")
        print(f"  Tactics:           {metadata.tactic_count:,}")
        print(f"  Integrity hash:    {metadata.integrity_hash}")
        print(f"  Imported at:       {metadata.imported_at.isoformat()}")
        print(f"  Snapshot path:     {snapshot_path}")
        print()
        return 0

    except Exception as exc:
        print(f"\n✗ Failed to import snapshot: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
