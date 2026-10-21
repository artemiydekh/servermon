import logging
from pathlib import Path
import sys
from typing import Any, Dict, Optional

from monitor.base import format_and_log_check
from monitor.ping import ping_check as _modular_ping_check
from monitor.tcp import tcp_check as _modular_tcp_check

BASE_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
log_dir = BASE_DIR / "storage"
log_dir.mkdir(parents=True, exist_ok=True)
log_file = log_dir / "monitor.log"

logging.basicConfig(
    filename=log_file,
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)


def _format_and_log(
    equipment: str,
    host: str,
    resolved_ip: Optional[str],
    check_type: str,
    port: Optional[Any],
    status: str,
    latency_ms: Optional[float],
    error_msg: Optional[str],
) -> Dict[str, Any]:
    """Legacy formatter preserving backward compatibility for callers and logs."""
    return format_and_log_check(
        equipment=equipment,
        host=host,
        resolved_ip=resolved_ip,
        check_type=check_type,
        port=port,
        status=status,
        latency_ms=latency_ms,
        error_msg=error_msg,
    )


def TCP_check(
    equipment: str,
    host: str,
    port: int,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Legacy facade for TCP check delegating to modular monitor.tcp."""
    return _modular_tcp_check(equipment=equipment, host=host, ports=[port], timeout=timeout)


def ping_check(
    equipment: str,
    host: str,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Legacy facade for ping check delegating to modular monitor.ping."""
    return _modular_ping_check(equipment=equipment, host=host, timeout=timeout)
