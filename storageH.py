import json
import sys
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional

BASE_DIR = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
TARGETS_FILE = CONFIG_DIR / "targets.json"
LOG_FILE = BASE_DIR / "storage" / "monitor.log"


def get_recent_logs(max_lines: int = 150) -> str:
    """Reads the last `max_lines` from the active audit log file."""
    if not LOG_FILE.exists():
        return (
            f"[System Note] No log file detected yet at {LOG_FILE}.\n"
            "Trigger a check using 'Check Now' to record events."
        )

    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            if not lines:
                return f"[System Note] Log file exists at {LOG_FILE}, but it is currently empty."
            return "".join(lines[-max_lines:])
    except OSError as e:
        return f"[System Error] Could not read log file: {e}"


def load_targets() -> List[Dict[str, Any]]:
    """Loads target configurations from targets.json."""
    try:
        with open(TARGETS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def save_targets(targets: List[Dict[str, Any]]) -> bool:
    """Persists target configurations to targets.json."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(TARGETS_FILE, "w", encoding="utf-8") as f:
            json.dump(targets, f, indent=2)
        return True
    except OSError:
        return False


def create_target_entry(
    name: str,
    host: str,
    check_type: str,
    port: Optional[int] = None
) -> Dict[str, Any]:
    """Constructs a validated server target dictionary with default metrics."""
    cleaned_name = name.strip()
    cleaned_host = host.strip()
    normalized_type = check_type.strip().upper()

    resolved_port: Optional[int] = None
    if port is not None:
        try:
            resolved_port = int(port)
        except (ValueError, TypeError):
            resolved_port = 80 if normalized_type == "TCP" else None
    elif normalized_type == "TCP":
        resolved_port = 80

    return {
        "id": f"target-{uuid.uuid4().hex[:8]}",
        "name": cleaned_name,
        "host": cleaned_host,
        "resolved_ip": None,
        "check_type": normalized_type,
        "port": resolved_port,
        "status": "PENDING",
        "response_time_ms": None,
        "total_response_time_ms": 0.0,
        "avg_response_time_ms": None,
        "last_checked": None,
        "error": None,
        "tcp_status": "STANDBY",
        "tcp_latency_ms": None,
        "icmp_status": "STANDBY",
        "icmp_latency_ms": None,
        "latency_delta_ms": None,
        "delta_analysis": "Run verification to compute protocol delta",
        "successes": 0,
        "failures": 0,
        "tcp_successes": 0,
        "tcp_failures": 0,
        "ping_successes": 0,
        "ping_failures": 0,
    }