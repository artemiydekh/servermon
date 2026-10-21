from monitor.base import BaseCheck, format_and_log_check
from monitor.dns import DnsCheck, dns_check
from monitor.http import HttpCheck, http_check
from monitor.ping import PingCheck, ping_check
from monitor.registry import (
    get_check,
    list_checks,
    register_check,
    run_check,
    run_checks_for_target,
)
from monitor.snmp import SnmpCheck, snmp_check
from monitor.tcp import TcpCheck, tcp_check
from monitor.traffic import (
    TrafficCheck,
    analyze_traffic_metrics,
    discover_tshark,
    traffic_check,
)

# Backward-compatible legacy aliases for callers importing monitor as a package
TCP_check = tcp_check
_format_and_log = format_and_log_check

__all__ = [
    "BaseCheck",
    "format_and_log_check",
    "_format_and_log",
    "ping_check",
    "PingCheck",
    "tcp_check",
    "TCP_check",
    "TcpCheck",
    "http_check",
    "HttpCheck",
    "dns_check",
    "DnsCheck",
    "snmp_check",
    "SnmpCheck",
    "traffic_check",
    "TrafficCheck",
    "discover_tshark",
    "analyze_traffic_metrics",
    "register_check",
    "get_check",
    "list_checks",
    "run_check",
    "run_checks_for_target",
]
