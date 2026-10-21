import platform
import re
import socket
import subprocess
import time
from typing import Any, Dict, Optional

from monitor.base import BaseCheck, format_and_log_check


def ping_check(
    equipment: str,
    host: str,
    timeout: float = 3.0,
    count: int = 1,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Performs an ICMP ping check via system ping and returns latency, packet loss, and IP."""
    status = "OFFLINE"
    resolved_ip = None
    response_time_ms = None
    min_rtt_ms = None
    max_rtt_ms = None
    avg_rtt_ms = None
    drop_rate_pct = 100.0
    packets_sent = count
    packets_received = 0
    error_msg = None

    try:
        resolved_ip = socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError, ValueError, TypeError) as e:
        error_msg = f"DNS resolution failed: {e}"
        return format_and_log_check(
            equipment=equipment,
            host=host,
            resolved_ip=None,
            check_type="PING",
            port=None,
            status="OFFLINE",
            latency_ms=None,
            error_msg=error_msg,
            extra_fields={
                "min_rtt_ms": None,
                "max_rtt_ms": None,
                "avg_rtt_ms": None,
                "drop_rate_pct": 100.0,
                "packets_sent": count,
                "packets_received": 0,
            },
        )

    is_windows = platform.system().lower() == "windows"
    if is_windows:
        command = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), resolved_ip]
        extra_args: Dict[str, Any] = {"creationflags": subprocess.CREATE_NO_WINDOW}
    else:
        command = ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), resolved_ip]
        extra_args = {}

    subproc_timeout = max(timeout + 2.0, (timeout * count) + 2.0)

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=subproc_timeout,
            **extra_args,
        )

        stdout = result.stdout or ""

        # Parse packet counts
        win_packets = re.search(
            r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)",
            stdout,
            re.IGNORECASE,
        )
        unix_packets = re.search(
            r"(\d+)\s+(?:packets\s+)?transmitted,\s*(\d+)\s+(?:packets\s+)?received",
            stdout,
            re.IGNORECASE,
        )

        if win_packets:
            packets_sent = int(win_packets.group(1))
            packets_received = int(win_packets.group(2))
        elif unix_packets:
            packets_sent = int(unix_packets.group(1))
            packets_received = int(unix_packets.group(2))

        # Parse loss percentage
        loss_match = re.search(r"\(?(\d+(?:\.\d+)?)%\s*(?:packet\s+)?loss\)?", stdout, re.IGNORECASE)
        if loss_match:
            drop_rate_pct = float(loss_match.group(1))
        elif packets_sent > 0:
            drop_rate_pct = round(((packets_sent - packets_received) / packets_sent) * 100.0, 1)

        # Parse latency
        win_rtt = re.search(
            r"Minimum\s*=\s*(\d+(?:\.\d+)?)\s*ms,\s*Maximum\s*=\s*(\d+(?:\.\d+)?)\s*ms,\s*Average\s*=\s*(\d+(?:\.\d+)?)\s*ms",
            stdout,
            re.IGNORECASE,
        )
        unix_rtt = re.search(
            r"(?:rtt|round-trip)\s+min/avg/max(?:/mdev)?\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)",
            stdout,
            re.IGNORECASE,
        )

        if win_rtt:
            min_rtt_ms = round(float(win_rtt.group(1)), 2)
            max_rtt_ms = round(float(win_rtt.group(2)), 2)
            avg_rtt_ms = round(float(win_rtt.group(3)), 2)
        elif unix_rtt:
            min_rtt_ms = round(float(unix_rtt.group(1)), 2)
            avg_rtt_ms = round(float(unix_rtt.group(2)), 2)
            max_rtt_ms = round(float(unix_rtt.group(3)), 2)
        else:
            avg_match = re.search(r"Average\s*=\s*(\d+(?:\.\d+)?)\s*ms", stdout, re.IGNORECASE)
            if avg_match:
                avg_rtt_ms = round(float(avg_match.group(1)), 2)
                min_rtt_ms = avg_rtt_ms
                max_rtt_ms = avg_rtt_ms
            else:
                time_matches = re.findall(r"time[=<](\d+(?:\.\d+)?)\s*ms", stdout, re.IGNORECASE)
                if time_matches:
                    times = [float(t) for t in time_matches]
                    min_rtt_ms = round(min(times), 2)
                    max_rtt_ms = round(max(times), 2)
                    avg_rtt_ms = round(sum(times) / len(times), 2)

        if result.returncode == 0 and packets_received > 0:
            response_time_ms = avg_rtt_ms
            if drop_rate_pct == 0.0:
                status = "ONLINE"
                error_msg = None
            else:
                status = "DEGRADED"
                error_msg = f"Packet drop rate {drop_rate_pct}%"
        else:
            status = "OFFLINE"
            error_msg = "Host unreachable or packet dropped"

    except subprocess.TimeoutExpired:
        status = "OFFLINE"
        error_msg = f"Ping process timed out after {timeout}s"
    except OSError as e:
        status = "OFFLINE"
        error_msg = f"Failed to invoke system ping command: {e}"
    except Exception as e:
        status = "OFFLINE"
        error_msg = f"Unexpected ping failure: {e}"

    return format_and_log_check(
        equipment=equipment,
        host=host,
        resolved_ip=resolved_ip,
        check_type="PING",
        port=None,
        status=status,
        latency_ms=response_time_ms,
        error_msg=error_msg,
        extra_fields={
            "min_rtt_ms": min_rtt_ms,
            "max_rtt_ms": max_rtt_ms,
            "avg_rtt_ms": avg_rtt_ms,
            "drop_rate_pct": drop_rate_pct,
            "packets_sent": packets_sent,
            "packets_received": packets_received,
        },
    )


class PingCheck(BaseCheck):
    """ICMP Ping check implementation."""

    def __init__(self):
        super().__init__("PING")

    def check(self, equipment: str, host: str, **kwargs: Any) -> Dict[str, Any]:
        return ping_check(equipment, host, **kwargs)
