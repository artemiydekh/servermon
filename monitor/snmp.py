import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from monitor.base import BaseCheck, format_and_log_check


# --- BER / ASN.1 Encoders ---

def _encode_length(length: int) -> bytes:
    """Encodes length in BER format."""
    if length < 128:
        return bytes([length])
    len_bytes = []
    temp = length
    while temp > 0:
        len_bytes.append(temp & 0xFF)
        temp >>= 8
    len_bytes.reverse()
    return bytes([0x80 | len(len_bytes)]) + bytes(len_bytes)


def _encode_tlv(tag: int, value: bytes) -> bytes:
    """Encodes a Tag-Length-Value construct."""
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(val: int) -> bytes:
    """Encodes a signed integer in BER format."""
    if val == 0:
        return _encode_tlv(0x02, b"\x00")
    res = []
    temp = val
    if temp < 0:
        temp = (1 << 32) + temp
    while temp > 0:
        res.append(temp & 0xFF)
        temp >>= 8
    if val >= 0 and res[-1] & 0x80:
        res.append(0)
    res.reverse()
    return _encode_tlv(0x02, bytes(res))


def _encode_octet_string(val: bytes) -> bytes:
    """Encodes an octet string in BER format."""
    return _encode_tlv(0x04, val)


def _encode_null() -> bytes:
    """Encodes a NULL value."""
    return b"\x05\x00"


def _encode_oid(oid_str: str) -> bytes:
    """Encodes an OID string (e.g. '1.3.6.1.2.1.1.1.0') in BER format."""
    parts = [int(p) for p in oid_str.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError("Invalid OID")
    payload = bytearray([parts[0] * 40 + parts[1]])
    for sub_id in parts[2:]:
        if sub_id < 128:
            payload.append(sub_id)
        else:
            chunks = []
            temp = sub_id
            while temp > 0:
                chunks.append(temp & 0x7F)
                temp >>= 7
            for i in range(len(chunks) - 1, 0, -1):
                payload.append(chunks[i] | 0x80)
            payload.append(chunks[0])
    return _encode_tlv(0x06, bytes(payload))


# --- BER / ASN.1 Decoders ---

def _decode_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """Decodes a single TLV, returning (tag, value_bytes, next_offset)."""
    if offset >= len(data):
        raise ValueError("Offset exceeds data length")
    tag = data[offset]
    offset += 1
    first_len = data[offset]
    offset += 1
    if first_len < 128:
        length = first_len
    else:
        num_octets = first_len & 0x7F
        length = 0
        for _ in range(num_octets):
            length = (length << 8) | data[offset]
            offset += 1
    val = data[offset : offset + length]
    return tag, val, offset + length


def _decode_oid(data: bytes) -> str:
    """Decodes BER OID bytes into a string."""
    if not data:
        return ""
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    idx = 1
    while idx < len(data):
        sub_id = 0
        while idx < len(data):
            b = data[idx]
            idx += 1
            sub_id = (sub_id << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        parts.append(str(sub_id))
    return ".".join(parts)


def _decode_integer(data: bytes) -> int:
    """Decodes signed integer bytes."""
    if not data:
        return 0
    return int.from_bytes(data, byteorder="big", signed=True)


def _decode_unsigned(data: bytes) -> int:
    """Decodes unsigned integer / counter / gauge bytes."""
    if not data:
        return 0
    return int.from_bytes(data, byteorder="big", signed=False)


def _build_snmp_get_packet(community: str, request_id: int, oids: List[str]) -> bytes:
    """Builds a complete SNMPv2c GetRequest packet."""
    # 1. VarBindList
    varbind_bytes = bytearray()
    for oid in oids:
        encoded_oid = _encode_oid(oid)
        encoded_null = _encode_null()
        varbind = _encode_tlv(0x30, encoded_oid + encoded_null)
        varbind_bytes.extend(varbind)
    varbind_list = _encode_tlv(0x30, bytes(varbind_bytes))

    # 2. GetRequest PDU (0xA0)
    pdu_content = (
        _encode_integer(request_id)
        + _encode_integer(0)  # error-status = 0
        + _encode_integer(0)  # error-index = 0
        + varbind_list
    )
    pdu = _encode_tlv(0xA0, pdu_content)

    # 3. SNMP Message: version(1 for v2c), community, pdu
    message_content = (
        _encode_integer(1)  # SNMPv2c version is 1 (v1 is 0)
        + _encode_octet_string(community.encode("latin-1"))
        + pdu
    )
    return _encode_tlv(0x30, message_content)


def _parse_snmp_response(data: bytes, expected_req_id: int) -> Dict[str, Any]:
    """Parses SNMPv2c GetResponse PDU and returns a dictionary of {oid_str: parsed_val}."""
    results: Dict[str, Any] = {}
    try:
        tag, msg_val, _ = _decode_tlv(data, 0)
        if tag != 0x30:
            return {}

        # Decode version
        _, ver_bytes, off = _decode_tlv(msg_val, 0)
        # Decode community
        _, comm_bytes, off = _decode_tlv(msg_val, off)
        # Decode PDU
        pdu_tag, pdu_val, _ = _decode_tlv(msg_val, off)
        if pdu_tag != 0xA2:  # GetResponse PDU tag
            return {}

        # Inside PDU: request-id, error-status, error-index, VarBindList
        _, req_id_bytes, pdu_off = _decode_tlv(pdu_val, 0)
        req_id = _decode_integer(req_id_bytes)
        if req_id != expected_req_id:
            return {}

        _, err_status_bytes, pdu_off = _decode_tlv(pdu_val, pdu_off)
        _, err_idx_bytes, pdu_off = _decode_tlv(pdu_val, pdu_off)
        _, varbind_list_val, _ = _decode_tlv(pdu_val, pdu_off)

        # Iterate VarBinds
        vb_off = 0
        while vb_off < len(varbind_list_val):
            vb_tag, vb_val, vb_off = _decode_tlv(varbind_list_val, vb_off)
            if vb_tag != 0x30:
                continue
            oid_tag, oid_bytes, val_off = _decode_tlv(vb_val, 0)
            oid_str = _decode_oid(oid_bytes)

            val_tag, val_bytes, _ = _decode_tlv(vb_val, val_off)

            if val_tag == 0x02:  # INTEGER
                val = _decode_integer(val_bytes)
            elif val_tag == 0x04:  # OCTET STRING
                val = val_bytes.decode("utf-8", errors="replace")
            elif val_tag in (0x41, 0x42, 0x43):  # Counter32, Gauge32, TimeTicks
                val = _decode_unsigned(val_bytes)
            elif val_tag in (0x80, 0x81, 0x82):  # NoSuchObject, NoSuchInstance, EndOfMibView
                val = None
            else:
                val = val_bytes

            results[oid_str] = val
    except Exception:
        pass
    return results


def _format_uptime_ticks(ticks: Optional[int]) -> Optional[str]:
    """Formats SNMP timeticks (hundredths of a second) into a human readable string."""
    if ticks is None:
        return None
    total_sec = ticks // 100
    days = total_sec // 86400
    hours = (total_sec % 86400) // 3600
    minutes = (total_sec % 3600) // 60
    seconds = total_sec % 60
    if days > 0:
        return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def snmp_check(
    equipment: str,
    host: str,
    port: int = 161,
    community: str = "public",
    version: str = "2c",
    timeout: float = 3.0,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Queries MIB-II sysUpTime, sysDescr and Host Resources CPU/RAM/Disk via SNMPv2c."""
    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            raise ValueError(f"Port out of range 1-65535: {port}")
    except (ValueError, TypeError) as e:
        return format_and_log_check(
            equipment=equipment,
            host=host,
            resolved_ip=None,
            check_type="SNMP",
            port=161,
            status="OFFLINE",
            latency_ms=None,
            error_msg=f"Invalid port: {e}",
            extra_fields={
                "sys_uptime": None,
                "sys_uptime_ticks": None,
                "sys_descr": None,
                "cpu_load_pct": None,
                "cpu_cores": None,
                "ram_usage_pct": None,
                "ram_total_mb": None,
                "ram_used_mb": None,
                "disk_usage_pct": None,
                "disk_total_gb": None,
                "disk_used_gb": None,
            },
        )

    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError, ValueError, TypeError) as e:
        error_msg = f"DNS resolution failed: {e}"
        return format_and_log_check(
            equipment=equipment,
            host=host,
            resolved_ip=None,
            check_type="SNMP",
            port=port_num,
            status="OFFLINE",
            latency_ms=None,
            error_msg=error_msg,
            extra_fields={
                "sys_uptime": None,
                "sys_uptime_ticks": None,
                "sys_descr": None,
                "cpu_load_pct": None,
                "cpu_cores": None,
                "ram_usage_pct": None,
                "ram_total_mb": None,
                "ram_used_mb": None,
                "disk_usage_pct": None,
                "disk_total_gb": None,
                "disk_used_gb": None,
            },
        )

    # Core OIDs to query across Host-Resources, UCD-SNMP, and Cisco MIBs
    oids_to_query = [
        "1.3.6.1.2.1.1.1.0",        # sysDescr.0
        "1.3.6.1.2.1.1.3.0",        # sysUpTime.0
        "1.3.6.1.2.1.25.3.3.1.2.1", # hrProcessorLoad.1 (CPU 1)
        "1.3.6.1.2.1.25.3.3.1.2.2", # hrProcessorLoad.2 (CPU 2)
        "1.3.6.1.2.1.25.2.2.0",      # hrMemorySize.0 (KB)
        "1.3.6.1.2.1.25.2.3.1.4.1", # hrStorageAllocationUnits.1
        "1.3.6.1.2.1.25.2.3.1.5.1", # hrStorageSize.1
        "1.3.6.1.2.1.25.2.3.1.6.1", # hrStorageUsed.1
        "1.3.6.1.2.1.25.2.3.1.4.2", # hrStorageAllocationUnits.2
        "1.3.6.1.2.1.25.2.3.1.5.2", # hrStorageSize.2
        "1.3.6.1.2.1.25.2.3.1.6.2", # hrStorageUsed.2
        "1.3.6.1.4.1.2021.10.1.3.1", # UCD-SNMP-MIB: 1-min load (ssCpuRawUser or laLoad.1)
        "1.3.6.1.4.1.2021.4.5.0",    # UCD-SNMP-MIB: memTotalReal (KB)
        "1.3.6.1.4.1.2021.4.6.0",    # UCD-SNMP-MIB: memAvailReal (KB)
        "1.3.6.1.4.1.2021.9.1.9.1",  # UCD-SNMP-MIB: dskPercent.1
        "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1", # Cisco: cpmCPUTotal5minRev
    ]

    req_id = 0x7B3A
    response_data = b""
    elapsed_ms: Optional[float] = None
    status = "OFFLINE"
    error_msg: Optional[str] = None

    t0 = time.perf_counter()
    try:
        packet = _build_snmp_get_packet(community, req_id, oids_to_query)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (resolved_ip, port_num))
            response_data, _ = sock.recvfrom(8192)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            status = "ONLINE"
    except socket.timeout:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        status = "OFFLINE"
        error_msg = f"SNMP request timed out after {timeout}s (UDP {port_num})"
    except UnicodeEncodeError as e:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        status = "OFFLINE"
        error_msg = f"SNMP community encoding error: {e}"
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        status = "OFFLINE"
        error_msg = f"SNMP network error: {e}"

    sys_descr: Optional[str] = None
    sys_uptime_ticks: Optional[int] = None
    sys_uptime_str: Optional[str] = None
    cpu_load_pct: Optional[float] = None
    cpu_cores: Optional[int] = None
    ram_usage_pct: Optional[float] = None
    ram_total_mb: Optional[float] = None
    ram_used_mb: Optional[float] = None
    disk_usage_pct: Optional[float] = None
    disk_total_gb: Optional[float] = None
    disk_used_gb: Optional[float] = None

    if status == "ONLINE" and response_data:
        parsed = _parse_snmp_response(response_data, req_id)
        if not parsed:
            # Maybe agent responded with an error or truncated/corrupted payload
            status = "DEGRADED"
            error_msg = "Corrupted or non-SNMP response received"
        else:
            # sysDescr
            if "1.3.6.1.2.1.1.1.0" in parsed and isinstance(parsed["1.3.6.1.2.1.1.1.0"], str):
                sys_descr = parsed["1.3.6.1.2.1.1.1.0"]

            # sysUpTime
            if "1.3.6.1.2.1.1.3.0" in parsed and isinstance(parsed["1.3.6.1.2.1.1.3.0"], int):
                sys_uptime_ticks = parsed["1.3.6.1.2.1.1.3.0"]
                sys_uptime_str = _format_uptime_ticks(sys_uptime_ticks)

            # CPU Extraction (Host-Resources -> UCD-SNMP -> Cisco)
            cpu_loads = []
            for oid in ("1.3.6.1.2.1.25.3.3.1.2.1", "1.3.6.1.2.1.25.3.3.1.2.2"):
                if oid in parsed and isinstance(parsed[oid], int):
                    cpu_loads.append(parsed[oid])
            if cpu_loads:
                cpu_load_pct = round(sum(cpu_loads) / len(cpu_loads), 1)
                cpu_cores = len(cpu_loads)
            elif "1.3.6.1.4.1.2021.10.1.3.1" in parsed:
                # UCD-SNMP 1-minute load
                ucd_val = parsed["1.3.6.1.4.1.2021.10.1.3.1"]
                try:
                    cpu_load_pct = round(float(ucd_val), 1)
                    cpu_cores = 1
                except (ValueError, TypeError):
                    pass
            elif "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1" in parsed and isinstance(parsed["1.3.6.1.4.1.9.9.109.1.1.1.1.5.1"], int):
                # Cisco CPU total 5min
                cpu_load_pct = float(parsed["1.3.6.1.4.1.9.9.109.1.1.1.1.5.1"])
                cpu_cores = 1

            # Storage & RAM extraction
            # Check Host-Resources storage slots 1 and 2
            for slot in (1, 2):
                units_oid = f"1.3.6.1.2.1.25.2.3.1.4.{slot}"
                size_oid = f"1.3.6.1.2.1.25.2.3.1.5.{slot}"
                used_oid = f"1.3.6.1.2.1.25.2.3.1.6.{slot}"
                units = parsed.get(units_oid)
                size = parsed.get(size_oid)
                used = parsed.get(used_oid)
                if isinstance(units, int) and isinstance(size, int) and isinstance(used, int) and size > 0:
                    pct = round((used / size) * 100.0, 1)
                    tot_bytes = units * size
                    used_bytes = units * used
                    if slot == 1 and ram_usage_pct is None:
                        ram_usage_pct = pct
                        ram_total_mb = round(tot_bytes / (1024 * 1024), 1)
                        ram_used_mb = round(used_bytes / (1024 * 1024), 1)
                    elif slot == 2 and disk_usage_pct is None:
                        disk_usage_pct = pct
                        disk_total_gb = round(tot_bytes / (1024**3), 2)
                        disk_used_gb = round(used_bytes / (1024**3), 2)

            # Fallback for hrMemorySize if RAM is not yet calculated
            if ram_total_mb is None and "1.3.6.1.2.1.25.2.2.0" in parsed and isinstance(parsed["1.3.6.1.2.1.25.2.2.0"], int):
                ram_total_mb = round(parsed["1.3.6.1.2.1.25.2.2.0"] / 1024.0, 1)

            # UCD-SNMP RAM Fallback
            if ram_usage_pct is None:
                tot_real = parsed.get("1.3.6.1.4.1.2021.4.5.0")
                avail_real = parsed.get("1.3.6.1.4.1.2021.4.6.0")
                if isinstance(tot_real, int) and isinstance(avail_real, int) and tot_real > 0:
                    used_real = max(0, tot_real - avail_real)
                    ram_usage_pct = round((used_real / tot_real) * 100.0, 1)
                    ram_total_mb = round(tot_real / 1024.0, 1)
                    ram_used_mb = round(used_real / 1024.0, 1)

            # UCD-SNMP Disk Fallback
            if disk_usage_pct is None and "1.3.6.1.4.1.2021.9.1.9.1" in parsed:
                try:
                    disk_usage_pct = float(parsed["1.3.6.1.4.1.2021.9.1.9.1"])
                except (ValueError, TypeError):
                    pass

        # Optional test simulation fallback if enabled for lab/demo targets
        if kwargs.get("simulate"):
            if cpu_load_pct is None:
                cpu_load_pct = 22.4
                cpu_cores = 4
            if ram_usage_pct is None:
                ram_usage_pct = 48.6
                ram_total_mb = 16384.0
                ram_used_mb = 7962.6
            if disk_usage_pct is None:
                disk_usage_pct = 61.2
                disk_total_gb = 512.0
                disk_used_gb = 313.3

    return format_and_log_check(
        equipment=equipment,
        host=host,
        resolved_ip=resolved_ip,
        check_type="SNMP",
        port=port_num,
        status=status,
        latency_ms=elapsed_ms,
        error_msg=error_msg,
        extra_fields={
            "sys_uptime": sys_uptime_str,
            "sys_uptime_ticks": sys_uptime_ticks,
            "sys_descr": sys_descr,
            "cpu_load_pct": cpu_load_pct,
            "cpu_cores": cpu_cores,
            "ram_usage_pct": ram_usage_pct,
            "ram_total_mb": ram_total_mb,
            "ram_used_mb": ram_used_mb,
            "disk_usage_pct": disk_usage_pct,
            "disk_total_gb": disk_total_gb,
            "disk_used_gb": disk_used_gb,
        },
    )


class SnmpCheck(BaseCheck):
    """SNMP Hardware Telemetry check implementation."""

    def __init__(self):
        super().__init__("SNMP")

    def check(self, equipment: str, host: str, **kwargs: Any) -> Dict[str, Any]:
        return snmp_check(equipment, host, **kwargs)
