"""Logger name constants.

Using centralized names prevents typos and ensures consistent
logger hierarchy across the application.
"""


class LogName:
    """Named loggers used throughout the application.

    All names are dot-separated to form a hierarchy rooted at ``argusprowl``.
    """

    ROOT: str = "argusprowl"
    CONFIG: str = "argusprowl.config"
    CORE: str = "argusprowl.core"
    EVENTS: str = "argusprowl.events"
    DI: str = "argusprowl.di"
    HEALTH: str = "argusprowl.health"
    CLI: str = "argusprowl.cli"
    UTILS: str = "argusprowl.utils"
    DETECTION: str = "argusprowl.detection"
    PLUGIN: str = "argusprowl.plugin"
    STORAGE: str = "argusprowl.storage"
    ALERT: str = "argusprowl.alert"
    INGESTION: str = "argusprowl.ingestion"
    COLLECTOR: str = "argusprowl.collector"
    COLLECTOR_MANAGER: str = "argusprowl.collector.manager"
    ATTCK: str = "argusprowl.attck"
