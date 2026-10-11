#!/usr/bin/env python3
"""argusprowl CLI entry point.

Provides command-line interface for starting the platform, checking health,
and verifying configuration.
"""

import argparse
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import argusprowl
from argusprowl.attck.knowledge_service import AttckKnowledgeService
from argusprowl.config.config_manager import ConfigManager
from argusprowl.constants.exit_codes import ExitCode
from argusprowl.constants.paths import ProjectPath
from argusprowl.core.application import Application
from argusprowl.exceptions.exceptions import ThreatHunterError


def _validate_stix_url(url: str) -> str:
    """Require an absolute HTTPS URL without embedded credentials."""
    try:
        parsed = urlsplit(url)
        # Accessing .port also validates malformed/out-of-range port values.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("STIX download URL is malformed.") from exc

    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(
            "STIX download URL must be an absolute HTTPS URL without embedded credentials."
        )
    return url


def create_parser() -> argparse.ArgumentParser:
    """Build command-line argument parser.

    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog="argusprowl",
        description="argusprowl - Modular Host-Based Threat Detection Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s v{argusprowl.__version__}",
        help="Show program version and exit.",
    )

    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=str(ProjectPath.DEFAULT_CONFIG_FILE),
        help="Path to YAML configuration file.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # ``run`` remains an alias for backward compatibility; ``start`` is canonical.
    run_parser = subparsers.add_parser(
        "start", aliases=["run"], help="Start argusprowl application."
    )
    run_parser.add_argument(
        "--config",
        type=str,
        help="Path to YAML configuration file.",
    )

    # 'health' subcommand
    health_parser = subparsers.add_parser(
        "health", help="Run system health check and display status."
    )
    health_parser.add_argument(
        "--config",
        type=str,
        help="Path to YAML configuration file.",
    )

    # 'replay' subcommand
    replay_parser = subparsers.add_parser(
        "replay", help="Replay Zeek log file through detection pipeline."
    )
    replay_parser.add_argument(
        "log_file",
        type=str,
        help="Path to Zeek log file to replay.",
    )

    subparsers.add_parser("validate-config", help="Load and validate configuration, then exit.")

    # 'server' subcommand
    server_parser = subparsers.add_parser(
        "server", help="Start the HTTP API server (requires api.enabled in config)."
    )
    server_parser.add_argument(
        "--config",
        type=str,
        help="Path to YAML configuration file.",
    )

    # 'import-snapshot' subcommand for ATT&CK STIX bundle
    import_parser = subparsers.add_parser(
        "import-snapshot",
        help="Import an ATT&CK STIX bundle snapshot into the knowledge service.",
    )
    import_parser.add_argument(
        "--config",
        type=str,
        help="Path to YAML configuration file.",
        default=str(ProjectPath.DEFAULT_CONFIG_FILE),
    )
    import_parser.add_argument(
        "--stix-path",
        type=str,
        help="Path to local STIX JSON file to import",
        default=None,
    )
    import_parser.add_argument(
        "--stix-url",
        type=str,
        help="URL to download STIX JSON from",
        default=None,
    )
    import_parser.add_argument(
        "--version",
        type=str,
        help="Target ATT&CK version (e.g., 14.0, 15.1). If specified, will fetch the appropriate STIX bundle.",
        default=None,
    )

    replay_parser.add_argument(
        "--config",
        type=str,
        help="Path to YAML configuration file.",
    )

    return parser


def main() -> int:
    """CLI execution entry point.

    Returns:
        ExitCode integer.
    """
    parser = create_parser()
    args = parser.parse_args()

    # Determine config file path
    config_path = getattr(args, "config", None) or str(ProjectPath.DEFAULT_CONFIG_FILE)

    # Command execution logic
    command = args.command or "start"
    application: Application | None = None

    try:
        if command == "validate-config":
            ConfigManager().load(config_path)
            print(f"Configuration valid: {config_path}")
            return ExitCode.SUCCESS

        if command == "import-snapshot":
            print("\n[+] Importing ATT&CK STIX bundle snapshot...")

            # Load config directly without starting the full application
            app_config = ConfigManager().load(config_path)
            attck_cfg = app_config.attck

            # Determine STIX source
            if args.stix_path:
                stix_data = Path(args.stix_path).read_bytes()
                source_desc = f"local file: {args.stix_path}"
            elif args.stix_url:
                import urllib.request

                print(f"    Downloading from: {args.stix_url}")
                validated_url = _validate_stix_url(args.stix_url)
                # Bandit B310 is suppressed only after HTTPS/host validation above.
                with urllib.request.urlopen(validated_url) as response:  # nosec B310
                    stix_data = response.read()
                source_desc = f"URL: {args.stix_url}"
            elif args.version:
                print(f"    Downloading ATT&CK version {args.version} STIX bundle...")
                import urllib.request

                stix_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
                print(f"    Downloading from: {stix_url}")
                validated_url = _validate_stix_url(stix_url)
                # Bandit B310 is suppressed only after HTTPS/host validation above.
                with urllib.request.urlopen(validated_url) as response:  # nosec B310
                    stix_data = response.read()
                source_desc = f"ATT&CK version {args.version}"
            else:
                print(
                    "[!] No STIX source specified. Use --stix-path, --stix-url, or --version.",
                    file=sys.stderr,
                )
                return ExitCode.CONFIG_ERROR

            # Create the knowledge service and import
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
            return ExitCode.SUCCESS

        application = Application(config_path=config_path)

        if command == "health":
            application.startup(start_api=False)
            status = application.health_check()
            print("\n=== argusprowl System Status ===")
            print(f"Overall Status: {status.status.upper()}")
            print(f"Version:        {status.version}")
            print(f"Uptime:         {status.uptime_seconds:.2f} seconds")
            print("\nComponents:")
            for comp in status.components:
                symbol = "✓" if comp.status == "healthy" else "..."
                print(f"  [{symbol}] {comp.name:<15}: {comp.status:<10} - {comp.message}")
            print("===================================\n")

        elif command in {"start", "run"}:
            print(f"\n[+] argusprowl v{argusprowl.__version__} initialized.")
            # Single-process mode: start the application (loading config,
            # wiring DI, starting the processing loop) before accessing
            # config-dependent values.  The API server is created but not
            # started as a daemon thread; run_foreground() binds uvicorn
            # in the foreground so the process blocks until interrupted.
            application.startup(start_api=False)
            print(f"[+] Environment: {application.config.environment}")
            print("[+] argusprowl system active. Press Ctrl+C to stop.")
            api_cfg = application.config.api
            if api_cfg.enabled:
                application.run_foreground(api_cfg.host, api_cfg.port)
            else:
                # No API — block on the processing loop until interrupted.
                try:
                    while application.is_running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass

        elif command == "replay":
            from argusprowl.replay.replay_engine import ReplayEngine

            print(f"\n[+] Starting replay of: {args.log_file}")
            replay_engine = ReplayEngine(log_path=args.log_file)
            stats = replay_engine.get_statistics()

            print(f"[+] Log file: {stats['reader']['log_path']}")
            print(f"[+] File size: {stats['reader']['file_size_bytes']} bytes")
            print("[+] Processing events through detection pipeline...\n")

            # Run replay with simple console output
            def on_detection(result):
                if result.matched:
                    print(f"[!] {result.description}")

            alerts = replay_engine.run_with_callbacks(on_detection=on_detection)

            print("\n[+] Replay complete.")
            print(f"[+] Events processed: {replay_engine.events_processed}")
            print(f"[+] Detections found: {replay_engine.alerts_generated}")
            print(f"[+] Alerts generated: {len(alerts)}\n")

        elif command == "server":
            application.startup(start_api=False)
            api_cfg = application.config.api
            if not api_cfg.enabled:
                print(
                    "[!] API server is disabled in configuration. Set api.enabled=true to start.",
                    file=sys.stderr,
                )
                return ExitCode.CONFIG_ERROR
            print(f"\n[+] argusprowl API server running at: http://{api_cfg.host}:{api_cfg.port}")
            print(f"    Interactive Docs available at: http://{api_cfg.host}:{api_cfg.port}/docs\n")
            print("[+] Press Ctrl+C to stop.\n")
            application.run_foreground(api_cfg.host, api_cfg.port)

        return ExitCode.SUCCESS

    except ThreatHunterError as exc:
        print(f"[!] argusprowl Error: {exc}", file=sys.stderr)
        return ExitCode.CONFIG_ERROR
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user.", file=sys.stderr)
        return ExitCode.KEYBOARD_INTERRUPT
    except Exception as exc:
        print(f"[!] Unexpected error: {exc}", file=sys.stderr)
        return ExitCode.GENERAL_ERROR
    finally:
        if application is not None:
            application.shutdown()


if __name__ == "__main__":
    sys.exit(main())
