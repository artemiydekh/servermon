from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from monitor.base import format_and_log_check
from monitor.dns import dns_check
from monitor.http import http_check
from monitor.ping import ping_check
from monitor.snmp import snmp_check
from monitor.tcp import tcp_check
from monitor.traffic import traffic_check

_CUSTOM_REGISTRY: Dict[str, Callable[..., Dict[str, Any]]] = {}

_BUILTIN_CHECKS = ("PING", "TCP", "HTTP", "HTTPS", "DNS", "SNMP", "TRAFFIC")


def register_check(name: str, check_func: Callable[..., Dict[str, Any]]) -> None:
    """Registers a new or custom check function."""
    _CUSTOM_REGISTRY[name.upper()] = check_func


def get_check(name: str) -> Optional[Callable[..., Dict[str, Any]]]:
    """Retrieves a registered check callable by name, resolving dynamically."""
    name_upper = name.upper()
    if name_upper in _CUSTOM_REGISTRY:
        return _CUSTOM_REGISTRY[name_upper]

    if name_upper == "PING":
        import monitor.ping as _mp
        return _mp.ping_check
    if name_upper == "TCP":
        import monitor.tcp as _mt
        return _mt.tcp_check
    if name_upper in ("HTTP", "HTTPS"):
        import monitor.http as _mh
        return _mh.http_check
    if name_upper == "DNS":
        import monitor.dns as _md
        return _md.dns_check
    if name_upper == "SNMP":
        import monitor.snmp as _ms
        return _ms.snmp_check
    if name_upper == "TRAFFIC":
        import monitor.traffic as _mtf
        return _mtf.traffic_check
    return None


def list_checks() -> List[str]:
    """Returns the names of all currently registered checkers."""
    all_names = set(_BUILTIN_CHECKS) | set(_CUSTOM_REGISTRY.keys())
    return sorted(list(all_names))


def run_check(check_name: str, equipment: str, host: str, **kwargs: Any) -> Dict[str, Any]:
    """Executes a single check by name."""
    fn = get_check(check_name)
    if not fn:
        return format_and_log_check(
            equipment=equipment,
            host=host,
            resolved_ip=None,
            check_type=check_name.upper(),
            port=kwargs.get("port"),
            status="OFFLINE",
            latency_ms=None,
            error_msg=f"Unknown check type: {check_name}",
        )
    if check_name.upper() == "HTTPS" and "check_type" not in kwargs:
        kwargs["check_type"] = "HTTPS"
    return fn(equipment=equipment, host=host, **kwargs)


def run_checks_for_target(
    target: Dict[str, Any],
    enabled_checks: Optional[List[str]] = None,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Executes all enabled checks for a target concurrently and aggregates results."""
    equipment = target.get("name") or target.get("equipment") or "Unknown"
    host = target.get("host") or ""
    target_id = target.get("id")

    # Determine enabled checks
    active_checks = enabled_checks
    if active_checks is None:
        active_checks = target.get("enabled_checks")
    if not active_checks:
        legacy_type = target.get("check_type", "TCP")
        active_checks = [legacy_type]

    # Deduplicate while preserving order
    clean_checks: List[str] = []
    for c in active_checks:
        c_upper = c.upper()
        if c_upper not in clean_checks:
            clean_checks.append(c_upper)

    check_configs = target.get("check_configs") or {}
    results: Dict[str, Dict[str, Any]] = {}

    def _execute_single(check_type: str) -> Tuple[str, Dict[str, Any]]:
        cfg = dict(check_configs.get(check_type, {}))
        if "timeout" not in cfg:
            cfg["timeout"] = timeout

        # Inject contextual target parameters
        if check_type == "TCP" and "ports" not in cfg and "port" not in cfg:
            if target.get("port"):
                cfg["port"] = target["port"]
        elif check_type in ("HTTP", "HTTPS") and "url" not in cfg:
            target_port = target.get("port")
            if check_type == "HTTPS" or target_port == 443:
                if target_port and target_port != 443:
                    cfg["url"] = f"https://{host}:{target_port}/"
                else:
                    cfg["url"] = f"https://{host}/"
            else:
                if target_port and target_port != 80:
                    cfg["url"] = f"http://{host}:{target_port}/"
                else:
                    cfg["url"] = f"http://{host}/"
            if "port" not in cfg and target_port:
                cfg["port"] = target_port
        elif check_type == "DNS":
            if "domain" not in cfg and "query_host" not in cfg:
                if target.get("domain"):
                    cfg["domain"] = target["domain"]
                elif target.get("query_host"):
                    cfg["query_host"] = target["query_host"]
                elif host:
                    cfg["domain"] = host
        elif check_type == "SNMP":
            if "port" not in cfg and target.get("port"):
                cfg["port"] = target["port"]
            if "community" not in cfg and target.get("community"):
                cfg["community"] = target["community"]
        elif check_type == "TRAFFIC":
            if "custom_tshark_path" not in cfg and target.get("tshark_path"):
                cfg["custom_tshark_path"] = target["tshark_path"]
            if "capture_duration_sec" not in cfg:
                cfg["capture_duration_sec"] = target.get("capture_duration_sec", 1.0)
            if "interface" not in cfg and target.get("interface"):
                cfg["interface"] = target["interface"]
            if "simulate" not in cfg and "simulate" in target:
                cfg["simulate"] = target["simulate"]
            if "allow_simulation" not in cfg and "allow_simulation" in target:
                cfg["allow_simulation"] = target["allow_simulation"]

        try:
            res = run_check(check_type, equipment=equipment, host=host, **cfg)
            return check_type, res
        except Exception as exc:
            err_res = format_and_log_check(
                equipment=equipment,
                host=host,
                resolved_ip=None,
                check_type=check_type,
                port=cfg.get("port"),
                status="OFFLINE",
                latency_ms=None,
                error_msg=f"Check execution exception: {exc}",
            )
            return check_type, err_res

    # Concurrent execution across all enabled checks
    max_workers = max(1, len(clean_checks))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_execute_single, c): c for c in clean_checks}
        for future in as_completed(futures):
            c_name, res = future.result()
            results[c_name] = res

    # Evaluate overall status
    statuses = [res.get("status", "OFFLINE") for res in results.values()]
    if not statuses:
        overall_status = "UNKNOWN"
    elif all(s == "ONLINE" for s in statuses):
        overall_status = "ONLINE"
    elif any(s == "ONLINE" for s in statuses):
        overall_status = "DEGRADED"
    elif any(s == "WARNING" for s in statuses):
        overall_status = "WARNING"
    else:
        overall_status = "OFFLINE"

    # Determine primary latency (prefer PING, then TCP, then HTTP, then first available)
    primary_latency: Optional[float] = None
    for preferred in ("PING", "TCP", "HTTP", "HTTPS", "DNS", "SNMP"):
        if preferred in results and results[preferred].get("response_time_ms") is not None:
            primary_latency = results[preferred]["response_time_ms"]
            break
    if primary_latency is None:
        for res in results.values():
            if res.get("response_time_ms") is not None:
                primary_latency = res["response_time_ms"]
                break

    return {
        "target_id": target_id,
        "equipment": equipment,
        "host": host,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "overall_status": overall_status,
        "primary_latency_ms": primary_latency,
        "checks": results,
    }
