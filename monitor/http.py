import datetime
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from monitor.base import BaseCheck, format_and_log_check


class _RedirectTracker(urllib.request.HTTPRedirectHandler):
    """Tracks redirect status codes and URLs during HTTP request dispatch."""

    def __init__(self, max_redirects: int = 10, follow: bool = True):
        self.chain: List[Dict[str, Any]] = []
        self.max_redirects = max_redirects
        self.follow = follow

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Optional[urllib.request.Request]:
        self.chain.append({"status": code, "from": req.full_url, "to": newurl})
        if not self.follow:
            return None
        if len(self.chain) > self.max_redirects:
            raise urllib.error.HTTPError(req.full_url, code, "Too many redirects", headers, fp)
        try:
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        except Exception as e:
            if hasattr(e, "close"):
                try:
                    e.close()
                except Exception:
                    pass
            return urllib.request.Request(newurl, headers=getattr(req, "headers", {}), unverifiable=True)


def _audit_ssl_certificate(host: str, port: int, timeout: float, verify_ssl: bool) -> Dict[str, Any]:
    """Inspects the SSL certificate for expiration, issuer, and validity."""
    audit: Dict[str, Any] = {
        "enabled": True,
        "valid": False,
        "issuer": None,
        "subject": None,
        "expires_at": None,
        "days_remaining": None,
        "is_expired": False,
        "error": None,
    }

    ctx = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            try:
                cert = ssock.getpeercert()
            finally:
                try:
                    ssock.close()
                except Exception:
                    pass

            audit["valid"] = True
            if cert:
                # Parse issuer
                issuer_items: List[str] = []
                for rdn in cert.get("issuer", ()):
                    for attr, val in rdn:
                        issuer_items.append(f"{attr}={val}")
                audit["issuer"] = ", ".join(issuer_items) if issuer_items else None

                # Parse subject
                subject_items: List[str] = []
                for rdn in cert.get("subject", ()):
                    for attr, val in rdn:
                        subject_items.append(f"{attr}={val}")
                audit["subject"] = ", ".join(subject_items) if subject_items else None

                # Parse expiration date
                not_after = cert.get("notAfter")
                if not_after and isinstance(not_after, str):
                    audit["expires_at"] = not_after
                    exp_dt = None
                    for date_fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %Y %Z", "%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                        try:
                            exp_dt = datetime.datetime.strptime(not_after, date_fmt).replace(tzinfo=datetime.timezone.utc)
                            break
                        except Exception:
                            continue
                    if exp_dt:
                        now = datetime.datetime.now(datetime.timezone.utc)
                        days = (exp_dt - now).days
                        audit["days_remaining"] = days
                        audit["is_expired"] = days < 0
                    else:
                        audit["error"] = f"Failed to parse cert date: {not_after}"

    except ssl.SSLCertVerificationError as e:
        audit["valid"] = False
        audit["error"] = f"Certificate verification failed: {e}"
    except Exception as e:
        audit["valid"] = False
        audit["error"] = f"SSL handshake error: {e}"

    return audit


def http_check(
    equipment: str,
    host: str,
    url: Optional[str] = None,
    port: Optional[int] = None,
    method: str = "GET",
    follow_redirects: bool = True,
    max_redirects: int = 10,
    verify_ssl: bool = True,
    timeout: float = 5.0,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Validates HTTP/HTTPS response, redirect chain, and SSL certificate health."""
    target_url = url
    check_proto = kwargs.get("check_type") or ("HTTPS" if port == 443 else "HTTP")
    try:
        if not target_url:
            if check_proto == "HTTPS" or port == 443:
                target_url = f"https://{host}:{port}/" if port and port != 443 else f"https://{host}/"
            elif port and port != 80:
                target_url = f"http://{host}:{port}/"
            else:
                target_url = f"http://{host}/"
        else:
            if not (target_url.startswith("http://") or target_url.startswith("https://")):
                target_url = f"https://{target_url}" if (check_proto == "HTTPS" or port == 443) else f"http://{target_url}"

        parsed = urllib.parse.urlsplit(target_url)
        target_host = parsed.hostname or host
        raw_port = parsed.port
        target_port = raw_port or (443 if parsed.scheme == "https" else 80)
        if not (1 <= target_port <= 65535):
            raise ValueError(f"Port out of range 1-65535: {target_port}")
        is_https = parsed.scheme == "https"
    except Exception as e:
        safe_port = port if isinstance(port, int) and 1 <= port <= 65535 else 80
        return format_and_log_check(
            equipment=equipment,
            host=host,
            resolved_ip=None,
            check_type=check_proto,
            port=safe_port,
            status="OFFLINE",
            latency_ms=None,
            error_msg=f"Invalid URL or port: {e}",
            extra_fields={
                "status_code": None,
                "reason": None,
                "url": target_url or "",
                "final_url": target_url or "",
                "redirect_chain": [],
                "redirect_count": 0,
                "ssl": None,
                "ssl_audit": None,
            },
        )

    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(target_host)
    except (socket.gaierror, UnicodeError, ValueError, TypeError) as e:
        error_msg = f"DNS resolution failed: {e}"
        return format_and_log_check(
            equipment=equipment,
            host=host,
            resolved_ip=None,
            check_type=check_proto,
            port=target_port,
            status="OFFLINE",
            latency_ms=None,
            error_msg=error_msg,
            extra_fields={
                "status_code": None,
                "reason": None,
                "url": target_url,
                "final_url": target_url,
                "redirect_chain": [],
                "redirect_count": 0,
                "ssl": None,
                "ssl_audit": None,
            },
        )

    # SSL Audit if HTTPS
    ssl_audit: Optional[Dict[str, Any]] = None
    if is_https:
        ssl_audit = _audit_ssl_certificate(target_host, target_port, timeout, verify_ssl)

    tracker = _RedirectTracker(max_redirects=max_redirects, follow=follow_redirects)
    ssl_ctx = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
    https_handler = urllib.request.HTTPSHandler(context=ssl_ctx)
    opener = urllib.request.build_opener(tracker, https_handler)

    req = urllib.request.Request(
        target_url,
        method=method.upper(),
        headers={"User-Agent": "ServerMon/2.0 (Modular HTTP Monitor)"},
    )

    status = "OFFLINE"
    status_code: Optional[int] = None
    reason: Optional[str] = None
    final_url = target_url
    elapsed_ms: Optional[float] = None
    error_msg: Optional[str] = None

    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as response:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            status_code = getattr(response, "status", getattr(response, "code", None))
            reason = getattr(response, "reason", "OK")
            final_url = response.geturl()

            if status_code and 200 <= status_code < 400:
                status = "ONLINE"
            else:
                status = "OFFLINE"
                error_msg = f"HTTP {status_code}: {reason}"

    except urllib.error.HTTPError as e:
        try:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            status_code = e.code
            reason = e.reason
            final_url = e.url
            if not follow_redirects and status_code and 200 <= status_code < 400:
                status = "ONLINE"
                error_msg = None
            else:
                status = "OFFLINE"
                error_msg = f"HTTP {status_code}: {reason}"
        finally:
            try:
                e.close()
            except Exception:
                pass
    except urllib.error.URLError as e:
        status = "OFFLINE"
        error_msg = f"URL error: {e.reason}"
    except socket.timeout:
        status = "OFFLINE"
        error_msg = f"HTTP request timed out after {timeout}s"
    except Exception as e:
        status = "OFFLINE"
        error_msg = f"HTTP request failed: {e}"

    if is_https and ssl_audit:
        if ssl_audit.get("is_expired"):
            status = "OFFLINE"
            error_msg = "SSL certificate expired"
        elif verify_ssl and not ssl_audit.get("valid"):
            status = "OFFLINE"
            if not error_msg:
                error_msg = ssl_audit.get("error") or "SSL verification failure"

    return format_and_log_check(
        equipment=equipment,
        host=host,
        resolved_ip=resolved_ip,
        check_type=check_proto,
        port=target_port,
        status=status,
        latency_ms=elapsed_ms,
        error_msg=error_msg,
        extra_fields={
            "status_code": status_code,
            "reason": reason,
            "url": final_url,
            "final_url": final_url,
            "redirect_chain": tracker.chain,
            "redirect_count": len(tracker.chain),
            "ssl": ssl_audit,
            "ssl_audit": ssl_audit,
        },
    )


class HttpCheck(BaseCheck):
    """HTTP/HTTPS & SSL Audit check implementation."""

    def __init__(self):
        super().__init__("HTTP")

    def check(self, equipment: str, host: str, **kwargs: Any) -> Dict[str, Any]:
        return http_check(equipment, host, **kwargs)
