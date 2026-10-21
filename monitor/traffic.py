import os
import platform
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional

from monitor.base import BaseCheck, format_and_log_check


def discover_tshark(custom_path: Optional[str] = None) -> Optional[str]:
    """Dynamically locates a working tshark executable across PATH and standard OS locations."""
    candidates: List[str] = []
    if custom_path:
        candidates.append(custom_path)

    which_path = shutil.which("tshark") or shutil.which("tshark.exe")
    if which_path:
        candidates.append(which_path)

    is_windows = platform.system().lower() == "windows"
    if is_windows:
        prog_files = os.environ.get("ProgramFiles", "C:\\Program Files")
        prog_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
        candidates.extend([
            os.path.join(prog_files, "Wireshark", "tshark.exe"),
            os.path.join(prog_files_x86, "Wireshark", "tshark.exe"),
            "C:\\Wireshark\\tshark.exe",
        ])
    else:
        candidates.extend([
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
        ])

    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            try:
                extra = {"creationflags": subprocess.CREATE_NO_WINDOW} if is_windows else {}
                res = subprocess.run([path, "-v"], capture_output=True, timeout=2.0, **extra)
                if res.returncode == 0:
                    return os.path.abspath(path)
            except Exception:
                continue
    return None


def analyze_traffic_metrics(
    packet_count: int,
    duration_sec: float,
    syn_count: int,
    unique_ports_contacted: int,
    syn_threshold_pps: float = 50.0,
    sweep_threshold_ports: int = 10,
) -> Dict[str, Any]:
    """Calculates PPS and evaluates SYN flood and port sweep anomaly heuristics."""
    safe_duration = max(duration_sec, 0.001)
    pps = round(packet_count / safe_duration, 2)
    syn_pps = round(syn_count / safe_duration, 2)

    is_syn_flood = syn_pps >= syn_threshold_pps and syn_count >= 10
    is_port_sweep = unique_ports_contacted >= sweep_threshold_ports

    threat_reasons: List[str] = []
    if is_syn_flood:
        threat_reasons.append(f"High SYN rate detected: {syn_pps} PPS (threshold: {syn_threshold_pps})")
    if is_port_sweep:
        threat_reasons.append(f"Port sweep pattern: {unique_ports_contacted} distinct destination ports targeted (threshold: {sweep_threshold_ports})")

    if is_syn_flood or is_port_sweep:
        threat_level = "ATTACK WARNING"
        status = "WARNING"
    elif pps > 100.0 or syn_pps > 20.0:
        threat_level = "SUSPICIOUS"
        status = "WARNING"
        threat_reasons.append(f"Elevated traffic volume: {pps} PPS")
    else:
        threat_level = "NORMAL"
        status = "ONLINE"

    return {
        "pps": pps,
        "syn_pps": syn_pps,
        "is_syn_flood": is_syn_flood,
        "is_port_sweep": is_port_sweep,
        "threat_level": threat_level,
        "threat_reasons": threat_reasons,
        "status": status,
    }


def traffic_check(
    equipment: str,
    host: str,
    interface: str = "any",
    capture_duration_sec: float = 3.0,
    syn_threshold_pps: float = 50.0,
    sweep_threshold_ports: int = 10,
    custom_tshark_path: Optional[str] = None,
    timeout: Optional[float] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Captures network traffic via tshark and analyzes PPS and attack heuristics."""
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError, ValueError, TypeError) as e:
        error_msg = f"DNS resolution failed: {e}"
        return format_and_log_check(
            equipment=equipment,
            host=host,
            resolved_ip=None,
            check_type="TRAFFIC",
            port=None,
            status="OFFLINE",
            latency_ms=None,
            error_msg=error_msg,
            extra_fields={
                "tshark_available": False,
                "tshark_path": None,
                "duration_sec": capture_duration_sec,
                "packet_count": 0,
                "pps": 0.0,
                "syn_count": 0,
                "syn_pps": 0.0,
                "unique_ports_contacted": 0,
                "threat_level": "NORMAL",
                "threat_reasons": [],
                "is_syn_flood": False,
                "is_port_sweep": False,
            },
        )

    tshark_bin = discover_tshark(custom_tshark_path)
    if not tshark_bin:
        if kwargs.get("simulate") or kwargs.get("allow_simulation") or kwargs.get("simulated"):
            safe_dur = max(0.1, float(capture_duration_sec))
            sim_pps = float(kwargs.get("simulated_pps", 18.4))
            metrics = analyze_traffic_metrics(
                packet_count=int(sim_pps * safe_dur),
                duration_sec=safe_dur,
                syn_count=int(sim_pps * 0.1 * safe_dur),
                unique_ports_contacted=4,
                syn_threshold_pps=syn_threshold_pps,
                sweep_threshold_ports=sweep_threshold_ports,
            )
            return format_and_log_check(
                equipment=equipment,
                host=host,
                resolved_ip=resolved_ip,
                check_type="TRAFFIC",
                port=None,
                status=metrics["status"],
                latency_ms=round(metrics["pps"], 2),
                error_msg=None,
                extra_fields={
                    "tshark_available": False,
                    "tshark_path": None,
                    "duration_sec": safe_dur,
                    "packet_count": int(sim_pps * safe_dur),
                    "pps": metrics["pps"],
                    "packet_rate_pps": metrics["pps"],
                    "peak_pps": metrics["pps"],
                    "syn_count": int(sim_pps * 0.1 * safe_dur),
                    "syn_pps": metrics["syn_pps"],
                    "unique_ports_contacted": 4,
                    "threat_level": metrics["threat_level"],
                    "threat_reasons": metrics["threat_reasons"],
                    "is_syn_flood": metrics["is_syn_flood"],
                    "is_port_sweep": metrics["is_port_sweep"],
                    "simulated": True,
                },
            )
        error_msg = "Wireshark (tshark.exe) not found on system"
        return format_and_log_check(
            equipment=equipment,
            host=host,
            resolved_ip=resolved_ip,
            check_type="TRAFFIC",
            port=None,
            status="OFFLINE",
            latency_ms=None,
            error_msg=error_msg,
            extra_fields={
                "tshark_available": False,
                "tshark_path": None,
                "duration_sec": capture_duration_sec,
                "packet_count": 0,
                "pps": 0.0,
                "packet_rate_pps": 0.0,
                "peak_pps": 0.0,
                "syn_count": 0,
                "syn_pps": 0.0,
                "unique_ports_contacted": 0,
                "threat_level": "NORMAL",
                "threat_reasons": [],
                "is_syn_flood": False,
                "is_port_sweep": False,
            },
        )

    # Invoke tshark for live capture
    is_windows = platform.system().lower() == "windows"
    cmd = [
        tshark_bin,
        "-a", f"duration:{max(1, int(capture_duration_sec))}",
        "-T", "fields",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.dstport",
    ]
    if interface and interface != "any" and not interface.startswith("-"):
        cmd.extend(["-i", interface])
    if resolved_ip:
        cmd.extend(["-f", f"host {resolved_ip}"])

    extra_args: Dict[str, Any] = {"creationflags": subprocess.CREATE_NO_WINDOW} if is_windows else {}
    subproc_timeout = (timeout or capture_duration_sec) + 3.0

    packet_count = 0
    syn_count = 0
    unique_ports = set()
    error_msg: Optional[str] = None

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=subproc_timeout,
            **extra_args,
        )
        actual_duration = round(time.perf_counter() - t0, 2)
        if proc.returncode == 0:
            for line in (proc.stdout or "").splitlines():
                parts = line.strip().split("\t")
                if not parts or not any(parts):
                    continue
                packet_count += 1
                syn_flag = parts[0] if len(parts) > 0 else ""
                ack_flag = parts[1] if len(parts) > 1 else ""
                dst_port = parts[2] if len(parts) > 2 else ""

                if syn_flag == "1" and ack_flag in ("0", ""):
                    syn_count += 1
                if dst_port:
                    try:
                        unique_ports.add(int(dst_port))
                    except ValueError:
                        pass
        else:
            stderr_msg = (proc.stderr or "").strip()
            error_msg = f"tshark capture warning: {stderr_msg[:120]}"
    except subprocess.TimeoutExpired:
        actual_duration = capture_duration_sec
        error_msg = f"Capture duration timed out after {capture_duration_sec}s"
    except Exception as e:
        actual_duration = capture_duration_sec
        error_msg = f"Failed to execute tshark: {e}"

    metrics = analyze_traffic_metrics(
        packet_count=packet_count,
        duration_sec=actual_duration,
        syn_count=syn_count,
        unique_ports_contacted=len(unique_ports),
        syn_threshold_pps=syn_threshold_pps,
        sweep_threshold_ports=sweep_threshold_ports,
    )

    final_status = metrics["status"] if not error_msg else "WARNING"

    return format_and_log_check(
        equipment=equipment,
        host=host,
        resolved_ip=resolved_ip,
        check_type="TRAFFIC",
        port=None,
        status=final_status,
        latency_ms=round(metrics["pps"], 2),
        error_msg=error_msg,
        extra_fields={
            "tshark_available": True,
            "tshark_path": tshark_bin,
            "duration_sec": actual_duration,
            "packet_count": packet_count,
            "pps": metrics["pps"],
            "packet_rate_pps": metrics["pps"],
            "peak_pps": metrics["pps"],
            "syn_count": syn_count,
            "syn_pps": metrics["syn_pps"],
            "unique_ports_contacted": len(unique_ports),
            "threat_level": metrics["threat_level"],
            "threat_reasons": metrics["threat_reasons"],
            "is_syn_flood": metrics["is_syn_flood"],
            "is_port_sweep": metrics["is_port_sweep"],
        },
    )


class TrafficCheck(BaseCheck):
    """Traffic & Security Anomaly check implementation."""

    def __init__(self):
        super().__init__("TRAFFIC")

    def check(self, equipment: str, host: str, **kwargs: Any) -> Dict[str, Any]:
        return traffic_check(equipment, host, **kwargs)
