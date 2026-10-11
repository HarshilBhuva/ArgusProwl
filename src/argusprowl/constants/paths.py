"""Project directory path constants.

All paths are relative to the project root directory and resolved
at import time so they remain stable regardless of the working directory.
"""

from pathlib import Path


class ProjectPath:
    """Centralized project path constants.

    All paths are resolved relative to the project root, which is determined
    by walking up from this file's location.
    """

    ROOT: Path = Path(__file__).resolve().parents[3]

    # Top-level directories
    APP: Path = ROOT / "src" / "argusprowl"
    CONFIG_DIR: Path = ROOT / "config"
    DATA_DIR: Path = ROOT / "data"
    LOGS_DIR: Path = ROOT / "logs"
    RULES_DIR: Path = ROOT / "config" / "rules"
    REPORTS_DIR: Path = ROOT / "reports"
    TESTS_DIR: Path = ROOT / "tests"
    DOCS_DIR: Path = ROOT / "docs"
    SCRIPTS_DIR: Path = ROOT / "scripts"

    # Default files
    DEFAULT_CONFIG_FILE: Path = CONFIG_DIR / "default.yaml"
    DEFAULT_LOG_FILE: Path = LOGS_DIR / "argusprowl.log"
    DEFAULT_JSON_LOG_FILE: Path = LOGS_DIR / "argusprowl.json"
