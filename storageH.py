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


LEGACY_KEYS = {
    "tcp_status",
    "icmp_status",
    "tcp_latency_ms",
    "icmp_latency_ms",
    "latency_delta_ms",
    "delta_analysis",
    "tcp_successes",
    "tcp_failures",
    "ping_successes",
    "ping_failures",
}


def load_targets() -> List[Dict[str, Any]]:
    """Loads target configurations from targets.json with auto-hydration for multi-mode monitoring."""
    try:
        with open(TARGETS_FILE, "r", encoding="utf-8") as f:
            targets = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if isinstance(targets, list):
        for t in targets:
            if isinstance(t, dict):
                for k in LEGACY_KEYS:
                    t.pop(k, None)
                # Ensure multi-mode keys exist
                if "enabled_checks" not in t:
                    check_type = t.get("check_type", "TCP")
                    t["enabled_checks"] = [check_type.upper()] if check_type else ["TCP"]
                if "check_configs" not in t:
                    t["check_configs"] = {}
                if "history" not in t:
                    t["history"] = {}
    return targets


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
    check_type: str = "TCP",
    port: Optional[int] = None,
    enabled_checks: Optional[List[str]] = None,
    check_configs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Constructs a validated server target dictionary with default metrics."""
    cleaned_name = name.strip()
    cleaned_host = host.strip()
    normalized_type = check_type.strip().upper() if check_type else "TCP"

    resolved_port: Optional[int] = None
    if port is not None:
        try:
            resolved_port = int(port)
        except (ValueError, TypeError):
            resolved_port = 80 if normalized_type == "TCP" else None
    elif normalized_type == "TCP":
        resolved_port = 80

    if enabled_checks is None:
        resolved_enabled = [normalized_type]
    else:
        resolved_enabled = [c.strip().upper() for c in enabled_checks if c and c.strip()]
        if not resolved_enabled:
            resolved_enabled = [normalized_type]

    return {
        "id": f"target-{uuid.uuid4().hex[:8]}",
        "name": cleaned_name,
        "host": cleaned_host,
        "resolved_ip": None,
        "check_type": normalized_type,
        "enabled_checks": resolved_enabled,
        "check_configs": check_configs if isinstance(check_configs, dict) else {},
        "history": {},
        "port": resolved_port,
        "status": "PENDING",
        "response_time_ms": None,
        "total_response_time_ms": 0.0,
        "avg_response_time_ms": None,
        "last_checked": None,
        "error": None,
        "successes": 0,
        "failures": 0,
    }


def append_telemetry_sample(
    target: Dict[str, Any],
    check_type: str,
    sample: Dict[str, Any],
    max_samples: int = 60,
) -> None:
    """
    Appends a telemetry sample to target's rolling history buffer for a given check_type.
    Maintains a FIFO eviction window capped at max_samples.
    """
    if "history" not in target or not isinstance(target["history"], dict):
        target["history"] = {}

    norm_type = check_type.strip().upper()
    buf = target["history"].setdefault(norm_type, [])
    sample_copy = dict(sample)
    if not sample_copy.get("timestamp"):
        import datetime
        sample_copy["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    buf.append(sample_copy)

    if len(buf) > max_samples:
        del buf[:len(buf) - max_samples]