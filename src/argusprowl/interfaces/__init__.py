"""Contracts consumed by use cases and implemented by infrastructure adapters."""

__all__ = [
    "AlertProvider",
    "Collector",
    "Detector",
    "LogSource",
    "Parser",
    "Storage",
]


def __getattr__(name: str) -> type:
    modules = {
        "AlertProvider": "alert_provider",
        "Collector": "collector",
        "Detector": "detector",
        "LogSource": "log_source",
        "Parser": "parser",
        "Storage": "storage",
    }
    try:
        module_name = modules[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    module = __import__(f"app.interfaces.{module_name}", fromlist=[name])
    return getattr(module, name)
