import json
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional

# Root directory configuration
CONFIG_DIR = Path("config")
TARGETS_FILE = CONFIG_DIR / "targets.json"

LOG_FILE = Path("storage/monitor.log")


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
    """Reads config/targets.json. If absent or invalid, returns an empty list."""
    try:
        with open(TARGETS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def save_targets(targets: List[Dict[str, Any]]) -> bool:
    """
    Automically writes the list of targets to config/targets.json with indentation.
    """
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
    """
    Constructs a validated, fully initialized server target dictionary.
    
    -----------------------------------------------------------------------------
    WHY THIS FUNCTION EXISTS:
    -----------------------------------------------------------------------------
    When a user creates a new server target via the UI form or through automated
    scripts, the resulting JSON dictionary must match the schema expected by ALL
    subsystems:
      1. The main All Servers table (tblAllServers)
      2. The Dashboard quick view cards & recent checks table
      3. The Server Inspector page (which compares TCP vs ICMP side-by-side)
      4. The asynchronous batch verification worker (BatchCheckWorker)
      5. The single-target on-demand worker (SingleTargetWorker)
      6. The JSON persistence file (config/targets.json)

    If any expected key is omitted, downstream code might raise a KeyError or
    display blank/broken dashes in the graphical interface. By centralizing the
    dictionary creation here, every new target is guaranteed to be 100% healthy
    and "ready to work" immediately upon creation.
    
    Parameters:
        name       - Human-friendly label for the equipment (e.g. 'Primary Gateway').
        host       - Domain name ('google.com') or IPv4 address ('1.1.1.1').
        check_type - The primary scheduled verification protocol: 'TCP' or 'PING'.
        port       - Integer network port number (1-65535) for TCP, or None if ping.
        
    Returns:
        A dictionary populated with all identifiers, network options, and initialized metrics.
    """
    # Sanitize and normalize basic string inputs
    cleaned_name = name.strip()
    cleaned_host = host.strip()
    normalized_type = check_type.strip().upper()

    # Determine an integer port when valid, otherwise keep as None for pure PING checks
    resolved_port: Optional[int] = None
    if port is not None:
        try:
            resolved_port = int(port)
        except (ValueError, TypeError):
            resolved_port = 80 if normalized_type == "TCP" else None
    elif normalized_type == "TCP":
        # Default fallback for TCP if no port was explicitly passed
        resolved_port = 80

    return {
        # Unique identifier used for lookups in memory dictionaries and table UserRole data
        "id": f"target-{uuid.uuid4().hex[:8]}",

        # Display metadata
        "name": cleaned_name,
        "host": cleaned_host,

        # Resolved IPv4 address: initially None until the first DNS lookup succeeds
        "resolved_ip": None,

        # Configured primary scheduled check method ('TCP' or 'PING')
        "check_type": normalized_type,

        # Listening service port (applicable to TCP, optional/None for ICMP)
        "port": resolved_port,

        # Current high-level operational status ('PENDING', 'ONLINE', or 'OFFLINE')
        "status": "PENDING",

        # Latency of the most recent primary check (in milliseconds)
        "response_time_ms": None,

        # Rolling sum of all successful latency samples (used to compute arithmetic mean)
        "total_response_time_ms": 0.0,

        # Cumulative average latency across all historical successful runs
        "avg_response_time_ms": None,

        # Human-readable timestamp of the last verification attempt ('YYYY-MM-DD HH:MM:SS')
        "last_checked": None,

        # Error message string from the most recent run (None if successful)
        "error": None,

        # =========================================================================
        # DUAL-PROTOCOL INSPECTOR STATUS & LATENCY FIELDS
        # =========================================================================
        # The Server Inspector tab allows testing both TCP and ICMP protocols
        # independently on every single server. These fields store the distinct
        # outcomes of each protocol so they can be displayed in dedicated slots.
        
        # TCP-specific outcome ('STANDBY', 'ONLINE', or 'OFFLINE')
        "tcp_status": "STANDBY",

        # TCP socket handshake latency (in milliseconds)
        "tcp_latency_ms": None,

        # ICMP echo ping outcome ('STANDBY', 'ONLINE', or 'OFFLINE')
        "icmp_status": "STANDBY",

        # ICMP round-trip ping time (in milliseconds)
        "icmp_latency_ms": None,

        # Comparative overhead delta: (tcp_latency_ms - icmp_latency_ms)
        # Represents how many milliseconds the TCP handshake adds over raw ping.
        "latency_delta_ms": None,

        # Explanatory narrative describing what the delta means for this host
        "delta_analysis": "Run verification to compute protocol delta",

        # =========================================================================
        # COUNTERS: OVERALL & PROTOCOL-SPECIFIC
        # =========================================================================
        # Overall counters tally every scheduled check regardless of protocol
        "successes": 0,
        "failures": 0,

        # Dedicated counters for the Server Inspector dual summary cards:
        # Card 7: "TCP Checks (OK / Total)"
        "tcp_successes": 0,
        "tcp_failures": 0,

        # Card 8: "Ping Checks (OK / Total)"
        "ping_successes": 0,
        "ping_failures": 0,
    }