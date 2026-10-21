import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from monitor.base import BaseCheck, format_and_log_check


def _build_dns_query(domain: str, tx_id: int = 0x1234) -> bytes:
    """Builds a standard DNS query packet for an IPv4 'A' record (RFC 1035)."""
    # Header: ID, Flags (0x0100 = recursion desired), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    question = bytearray()
    clean_domain = domain.strip().rstrip(".")
    for part in clean_domain.split("."):
        encoded = part.encode("ascii", errors="ignore")
        if len(encoded) > 63:
            raise ValueError(f"DNS label exceeds 63 octets: {len(encoded)}")
        question.append(len(encoded))
        question.extend(encoded)
    question.append(0)  # Null terminator for QNAME
    # QTYPE=1 (A), QCLASS=1 (IN)
    question.extend(struct.pack("!HH", 1, 1))
    return header + bytes(question)


def _parse_dns_response(data: bytes, expected_tx_id: int) -> List[str]:
    """Parses a DNS response payload and extracts IPv4 addresses from the Answer section."""
    if len(data) < 12:
        return []
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if tx_id != expected_tx_id:
        return []
    # Check RCODE (lower 4 bits)
    if (flags & 0x000F) != 0:
        return []

    offset = 12
    # Skip Question Section
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:
                offset += 1  # 2-byte pointer
                break
            offset += length
        offset += 4  # QTYPE + QCLASS

    # Parse Answer Section
    ips: List[str] = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        # Skip NAME field
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                offset += 2
                break
            offset += 1 + length

        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):  # Type A (IPv4)
            ip_str = socket.inet_ntoa(data[offset : offset + 4])
            if ip_str not in ips:
                ips.append(ip_str)
        offset += rdlength

    return ips


def _query_benchmark_resolver(domain: str, resolver_ip: str, timeout: float) -> Tuple[List[str], Optional[float], Optional[str]]:
    """Sends a standard UDP DNS query to a benchmark resolver on port 53."""
    tx_id = 0x5678
    t0 = time.perf_counter()
    try:
        query = _build_dns_query(domain, tx_id)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (resolver_ip, 53))
            data, _ = sock.recvfrom(4096)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            ips = _parse_dns_response(data, tx_id)
            return ips, elapsed_ms, None
    except socket.timeout:
        return [], None, f"Benchmark resolver {resolver_ip} timed out"
    except Exception as e:
        return [], None, f"DNS query failed to {resolver_ip}: {e}"


def dns_check(
    equipment: str,
    host: str,
    benchmark_resolvers: Optional[List[str]] = None,
    record_type: str = "A",
    timeout: float = 3.0,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Compares local system DNS resolution against benchmark public resolvers."""
    resolvers = benchmark_resolvers or ["1.1.1.1", "8.8.8.8"]
    query_domain = kwargs.get("domain") or kwargs.get("query_host") or host

    # 1. Local system resolution
    system_ips: List[str] = []
    sys_latency_ms: Optional[float] = None
    sys_error: Optional[str] = None

    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(query_domain, None, socket.AF_INET, socket.SOCK_STREAM)
        sys_latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        for info in infos:
            ip = info[4][0]
            if ip not in system_ips:
                system_ips.append(ip)
    except (socket.gaierror, UnicodeError, ValueError, TypeError) as e:
        sys_error = f"Local DNS resolution failed: {e}"
    except Exception as e:
        sys_error = f"Unexpected local DNS resolution error: {e}"

    # 2. Benchmark resolver queries
    benchmark_ips: Dict[str, List[str]] = {}
    benchmark_latencies_ms: Dict[str, float] = {}

    for resolver in resolvers:
        ips, lat_ms, err = _query_benchmark_resolver(query_domain, resolver, timeout)
        benchmark_ips[resolver] = ips
        if lat_ms is not None:
            benchmark_latencies_ms[resolver] = lat_ms

    # 3. Analyze consistency and integrity
    status = "OFFLINE"
    integrity_status = "RESOLUTION_FAILED"
    dns_match = False
    error_msg: Optional[str] = None
    latency_delta_ms: Optional[float] = None

    all_bench_ips: List[str] = []
    for ips in benchmark_ips.values():
        for ip in ips:
            if ip not in all_bench_ips:
                all_bench_ips.append(ip)

    if not system_ips:
        status = "OFFLINE"
        integrity_status = "RESOLUTION_FAILED"
        dns_match = False
        error_msg = sys_error or "Local DNS returned no addresses"
    else:
        status = "ONLINE"
        if not all_bench_ips:
            integrity_status = "BENCHMARK_UNREACHABLE"
            dns_match = True
            error_msg = "Benchmark resolvers unreachable on UDP 53"
        else:
            sys_set = set(system_ips)
            bench_set = set(all_bench_ips)
            if sys_set == bench_set or sys_set.issubset(bench_set) or bench_set.issubset(sys_set) or bool(sys_set & bench_set):
                integrity_status = "VERIFIED_MATCH"
                dns_match = True
                error_msg = None
            else:
                integrity_status = "CDN_DIVERGENT"
                dns_match = False
                error_msg = "System and benchmark returned divergent IP addresses (CDN or anycast routing)"

    if sys_latency_ms is not None and benchmark_latencies_ms:
        avg_bench_lat = sum(benchmark_latencies_ms.values()) / len(benchmark_latencies_ms)
        latency_delta_ms = round(sys_latency_ms - avg_bench_lat, 2)

    resolved_ip = system_ips[0] if system_ips else None

    return format_and_log_check(
        equipment=equipment,
        host=host,
        resolved_ip=resolved_ip,
        check_type="DNS",
        port=53,
        status=status,
        latency_ms=sys_latency_ms,
        error_msg=error_msg,
        extra_fields={
            "system_ips": system_ips,
            "benchmark_ips": benchmark_ips,
            "benchmark_latencies_ms": benchmark_latencies_ms,
            "system_dns_latency_ms": sys_latency_ms,
            "benchmark_dns_latency_ms": (benchmark_latencies_ms.get("1.1.1.1") if "1.1.1.1" in benchmark_latencies_ms else (next(iter(benchmark_latencies_ms.values())) if benchmark_latencies_ms else None)),
            "domain": query_domain,
            "query_host": query_domain,
            "integrity_status": integrity_status,
            "dns_match": dns_match,
            "latency_delta_ms": latency_delta_ms,
        },
    )


class DnsCheck(BaseCheck):
    """DNS Integrity check implementation."""

    def __init__(self):
        super().__init__("DNS")

    def check(self, equipment: str, host: str, **kwargs: Any) -> Dict[str, Any]:
        return dns_check(equipment, host, **kwargs)
