import re
import socket
import time
import logging
import sys
from pathlib import Path
import subprocess
import platform

BASE_DIR = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
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


def TCP_check(
    equipment: str,
    host: str,
    port: int,
    timeout: float = 3.0,
) -> dict:
    """Performs a TCP port connectivity check and logs the result."""
    t0 = time.perf_counter()
    status = "OFFLINE"
    resolved_ip = None
    response_time_ms = None
    error_msg = None

    try:
        resolved_ip = socket.gethostbyname(host)
        with socket.create_connection((resolved_ip, port), timeout=timeout):
            status = "ONLINE"
            elapsed = (time.perf_counter() - t0) * 1000
            response_time_ms = round(elapsed, 2)

    except socket.gaierror as e:
        error_msg = f"DNS resolution error: {e}"
    except socket.timeout:
        error_msg = f"Timed out after {timeout}s"
    except ConnectionRefusedError:
        error_msg = "Connection refused (port closed)"
    except OSError as e:
        error_msg = f"Network error: {e}"
    except Exception as e:
        error_msg = f"Unexpected failure: {e}"

    return _format_and_log(equipment, host, resolved_ip, "TCP", port, status, response_time_ms, error_msg)


def ping_check(
    equipment: str,
    host: str,
    timeout: float = 3.0
) -> dict:
    """Performs an ICMP ping check via system ping and logs the result."""
    t0 = time.perf_counter()
    status = "OFFLINE"
    resolved_ip = None
    response_time_ms = None
    error_msg = None

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        error_msg = f"DNS resolution failed: {e}"
        return _format_and_log(equipment, host, resolved_ip, "PING", None, status, None, error_msg)

    is_windows = platform.system().lower() == "windows"
    if is_windows:
        command = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), resolved_ip]
        extra_args = {"creationflags": subprocess.CREATE_NO_WINDOW}
    else:
        command = ["ping", "-c", "1", "-W", str(int(timeout)), resolved_ip]
        extra_args = {}

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 1.0,
            **extra_args
        )

        if result.returncode == 0:
            status = "ONLINE"
            output_text = result.stdout
            rtt_match = re.search(r"time[=<](\d+(?:\.\d+)?)\s*ms", output_text, re.IGNORECASE)
            response_time_ms = round(float(rtt_match.group(1)), 2) if rtt_match else None
        else:
            error_msg = "Host unreachable or packet dropped"

    except subprocess.TimeoutExpired:
        error_msg = f"Ping process timed out after {timeout}s"
    except OSError as e:
        error_msg = f"Failed to invoke system ping command: {e}"
    except Exception as e:
        error_msg = f"Unexpected ping failure: {e}"

    return _format_and_log(equipment, host, resolved_ip, "PING", None, status, response_time_ms, error_msg)


def _format_and_log(equipment, host, resolved_ip, check_type, port, status, latency_ms, error_msg) -> dict:
    """Formats the result payload and writes the log entry."""
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
    (logging.info if status == "ONLINE" else logging.warning)(log_entry)

    return {
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
