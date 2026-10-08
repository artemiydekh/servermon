import re       # Used to extract the RTT value from the ping command's text output
import socket
import time
import logging
from pathlib import Path
import subprocess
import platform

# Align directly with project specifications: storage/monitor.log
BASE_DIR = Path(__file__).resolve().parent
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
    """
    Performs a TCP port check, records an audit log entry meeting all info requirements,
    and returns a dictionary ready for the GUI and storage layers.
    """
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
    """
    Performs an ICMP ping check via the OS native ping utility,
    logs the event across all 8 required fields, and returns a 
    structured status dictionary identical to TCP_check.
    """
    t0 = time.perf_counter()
    status = "OFFLINE"
    resolved_ip = None
    response_time_ms = None
    error_msg = None

    # 1. Resolve DNS hostname to IP address
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        error_msg = f"DNS resolution failed: {e}"
        return _format_and_log(equipment, host, resolved_ip, "PING", None, status, None, error_msg)

    # 2. Construct OS-specific ping command
    # Windows uses: ping -n 1 -w <milliseconds> <target>
    # Linux/macOS uses: ping -c 1 -W <seconds> <target>
    is_windows = platform.system().lower() == "windows"
    
    if is_windows:
        timeout_ms = int(timeout * 1000)
        command = ["ping", "-n", "1", "-w", str(timeout_ms), resolved_ip]
    else:
        command = ["ping", "-c", "1", "-W", str(int(timeout)), resolved_ip]

    # Windows-specific process flag: prevents black CMD popup windows from flashing
    extra_args = {}
    if is_windows:
        extra_args["creationflags"] = subprocess.CREATE_NO_WINDOW

    # 3. Execute Ping Subprocess and Parse Round-Trip Time from Output
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
    """Helper to record audit log entries and format result payloads identically."""
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

def Test_TCP_Ping():   
    print("Running TCP verification tests...")
    res_online = TCP_check(equipment="Google Web", host="google.com", port=443)
    print("Success test output:", res_online)

    res_offline = TCP_check(equipment="Dead Local Port", host="127.0.0.1", port=65432, timeout=1.0)
    print("Offline test output:", res_offline)

    res_dns_fail = TCP_check(equipment="Fake Domain", host="invalid-host-test.fake", port=80, timeout=1.0)
    print("DNS failure test output:", res_dns_fail)
