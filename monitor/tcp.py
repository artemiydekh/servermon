import socket
import time
from typing import Any, Dict, List, Optional, Union

from monitor.base import BaseCheck, format_and_log_check


def _parse_ports(ports: Union[List[int], str, int, None], fallback_port: Optional[int] = None) -> List[int]:
    """Parses port input into a list of unique valid integer port numbers."""
    raw_ports: List[Any] = []
    if fallback_port is not None and (ports is None or ports == 80):
        raw_ports = [fallback_port]
    elif isinstance(ports, int):
        raw_ports = [ports]
    elif isinstance(ports, str):
        parts = [p.strip() for p in ports.split(",") if p.strip()]
        for p in parts:
            try:
                raw_ports.append(int(p))
            except ValueError:
                pass
    elif isinstance(ports, (list, tuple, set)):
        raw_ports = list(ports)

    valid_ports: List[int] = []
    for p in raw_ports:
        try:
            port_num = int(p)
            if 1 <= port_num <= 65535 and port_num not in valid_ports:
                valid_ports.append(port_num)
        except (ValueError, TypeError):
            continue

    if not valid_ports:
        if fallback_port and 1 <= fallback_port <= 65535:
            valid_ports = [fallback_port]
        else:
            valid_ports = [80]

    return valid_ports


def tcp_check(
    equipment: str,
    host: str,
    ports: Union[List[int], str, int] = 80,
    timeout: float = 3.0,
    port: Optional[int] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Performs multi-port TCP connectivity checks and handshake latency timing."""
    target_ports = _parse_ports(ports, fallback_port=port)
    primary_port = target_ports[0]

    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError, ValueError, TypeError) as e:
        error_msg = f"DNS resolution error: {e}"
        return format_and_log_check(
            equipment=equipment,
            host=host,
            resolved_ip=None,
            check_type="TCP",
            port=primary_port,
            status="OFFLINE",
            latency_ms=None,
            error_msg=error_msg,
            extra_fields={
                "ports_tested": target_ports,
                "open_ports": [],
                "closed_ports": target_ports,
                "port_results": {p: {"status": "OFFLINE", "latency_ms": None, "error": error_msg} for p in target_ports},
            },
        )

    port_results: Dict[int, Dict[str, Any]] = {}
    latencies: List[float] = []

    for p in target_ports:
        t0 = time.perf_counter()
        conn_timeout = timeout
        try:
            with socket.create_connection((resolved_ip, p), timeout=conn_timeout):
                elapsed = (time.perf_counter() - t0) * 1000
                latency = round(elapsed, 2)
                latencies.append(latency)
                port_results[p] = {
                    "status": "ONLINE",
                    "latency_ms": latency,
                    "error": None,
                }
        except socket.timeout:
            port_results[p] = {
                "status": "OFFLINE",
                "latency_ms": None,
                "error": f"Timed out after {timeout}s",
            }
        except ConnectionRefusedError:
            port_results[p] = {
                "status": "OFFLINE",
                "latency_ms": None,
                "error": "Connection refused (port closed)",
            }
        except OSError as e:
            port_results[p] = {
                "status": "OFFLINE",
                "latency_ms": None,
                "error": f"Network error: {e}",
            }
        except Exception as e:
            port_results[p] = {
                "status": "OFFLINE",
                "latency_ms": None,
                "error": f"Unexpected failure: {e}",
            }

    open_ports = [p for p in target_ports if port_results[p]["status"] == "ONLINE"]
    closed_ports = [p for p in target_ports if port_results[p]["status"] != "ONLINE"]

    if len(open_ports) == len(target_ports):
        status = "ONLINE"
        error_msg = None
    elif len(open_ports) > 0:
        status = "DEGRADED"
        error_msg = f"Partial connectivity: open={open_ports}, closed={closed_ports}"
    else:
        status = "OFFLINE"
        first_err = port_results[primary_port]["error"] if primary_port in port_results else "All ports closed"
        error_msg = first_err or "Connection refused (port closed)"

    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None

    return format_and_log_check(
        equipment=equipment,
        host=host,
        resolved_ip=resolved_ip,
        check_type="TCP",
        port=primary_port,
        status=status,
        latency_ms=avg_latency,
        error_msg=error_msg,
        extra_fields={
            "ports_tested": target_ports,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "port_results": port_results,
        },
    )


class TcpCheck(BaseCheck):
    """TCP Multi-port check implementation."""

    def __init__(self):
        super().__init__("TCP")

    def check(self, equipment: str, host: str, **kwargs: Any) -> Dict[str, Any]:
        return tcp_check(equipment, host, **kwargs)
