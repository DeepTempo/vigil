"""SOC Daemon - Headless autonomous security operations service."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from services.daemon.config import DaemonConfig
    from services.daemon.main import SOCDaemon


def __getattr__(name: str):
    if name == "DaemonConfig":
        from services.daemon.config import DaemonConfig

        return DaemonConfig
    if name == "SOCDaemon":
        from services.daemon.main import SOCDaemon

        return SOCDaemon
    raise AttributeError(name)


__all__ = ["DaemonConfig", "SOCDaemon"]
