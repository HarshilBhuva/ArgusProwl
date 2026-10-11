#!/usr/bin/env python3
"""Script to import MITRE ATT&CK STIX bundle snapshot into ArgusProwl."""

import argparse
import sys
import urllib.request
from pathlib import Path

# Adjust path for ArgusProwl imports if running from scripts directory
sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))

from argusprowl.attck.knowledge_service import AttckKnowledgeService
from argusprowl.config.config_manager import ConfigManager


def main():
    """Main entry point for the import-snapshot script."""
    parser = argparse.ArgumentParser(description="Import MITRE ATT&CK STIX bundle snapshot")
    parser.add_argument(
        "--config",
        type=str,
        default="config/default.yaml",
        help="Path to YAML configuration file (default: config/default.yaml)",
    )
    parser.add_argument(
        "--stix-path",
        type=str,
        help="Path to local STIX bundle file (overrides --stix-url and --version)",
    )
    parser.add_argument(
        "--stix-url",
        type=str,
        help="URL to download STIX bundle from (overrides --version)",
    )
    parser.add_argument(
        "--version",
        type=str,
        help="ATT&CK version to download (e.g., '18.1')",
    )
    args = parser.parse_args()

    try:
        # Load configuration (no Application startup — avoids chicken-and-egg
        # problem where enabling ATT&CK requires a valid snapshot to start)
        config = ConfigManager.get_instance().load(args.config)

        # Determine STIX source
        if args.stix_path:
            stix_data = Path(args.stix_path).read_bytes()
            source_desc = f"local file: {args.stix_path}"
        elif args.stix_url:
            print(f"Downloading from: {args.stix_url}")
            with urllib.request.urlopen(args.stix_url) as response:
                stix_data = response.read()
            source_desc = f"URL: {args.stix_url}"
        elif args.version:
            print(f"Downloading ATT&CK version {args.version} STIX bundle...")
            # Using the official URL pattern
            stix_url = (
                f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                f"v{args.version}/enterprise-attack/enterprise-attack-{args.version}.json"
            )
            print(f"Downloading from: {stix_url}")
            with urllib.request.urlopen(stix_url) as response:
                stix_data = response.read()
            source_desc = f"ATT&CK version {args.version} (version-tagged upstream artifact)"
        else:
            print(
                "[!] No STIX source specified. Use --stix-path, --stix-url, or --version.",
                file=sys.stderr,
            )
            return 1

        # Import the snapshot
        attck_cfg = config.attck
        knowledge_service = AttckKnowledgeService(
            snapshot_path=attck_cfg.snapshot_path,
            previous_snapshot_path=attck_cfg.previous_snapshot_path or None,
            enabled=attck_cfg.enabled,
        )

        metadata = knowledge_service.import_snapshot(stix_data)

        print(f"[+] Successfully imported ATT&CK snapshot from {source_desc}")
        print(f"    Version: {metadata.version}")
        print(f"    Techniques: {metadata.technique_count}")
        print(f"    Tactics: {metadata.tactic_count}")
        print(f"    Integrity hash: {metadata.integrity_hash}")
        print(f"    Imported at: {metadata.imported_at.isoformat()}\n")

        return 0

    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
