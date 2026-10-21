import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional

BASE_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
log_dir = BASE_DIR / "storage"
log_dir.mkdir(parents=True, exist_ok=True)
log_file = log_dir / "monitor.log"

logger = logging.getLogger("servermon.monitor")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(file_handler)


def format_and_log_check(
    equipment: str,
    host: str,
    resolved_ip: Optional[str],
    check_type: str,
    port: Optional[Any],
    status: str,
    latency_ms: Optional[float],
    error_msg: Optional[str],
    extra_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Formats standardized check results and logs to storage/monitor.log."""
    elapsed_display = f"{latency_ms}ms" if latency_ms is not None else "N/A"
    port_display = str(port) if port is not None else "N/A"
    log_entry = (
        f"EQUIPMENT: {equipment} | "
        f"HOST: {host} (IP: {resolved_ip or 'Unresolved'}) | "
        f"TYPE: {check_type} | "
        f"PORT: {port_display} | "
        f"RESULT: {status} | "
        f"TIME: {elapsed_display} | "
        f"ERROR: {error_msg or 'None'}"
    )

    if status in ("ONLINE", "NORMAL", "VERIFIED_MATCH"):
        logger.info(log_entry)
    else:
        logger.warning(log_entry)

    result: Dict[str, Any] = {
        "equipment": equipment,
        "host": host,
        "resolved_ip": resolved_ip,
        "check_type": check_type,
        "port": port,
        "status": status,
        "response_time_ms": latency_ms,
        "error": error_msg,
        "log_entry": log_entry,
    }

    if extra_fields:
        result.update(extra_fields)

    return result


class BaseCheck:
    """Base class for modular monitoring checkers."""

    def __init__(self, name: str):
        self.name = name

    def check(self, equipment: str, host: str, **kwargs: Any) -> Dict[str, Any]:
        raise NotImplementedError("Subclasses must implement check()")
