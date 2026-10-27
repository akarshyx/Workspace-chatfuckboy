"""Use certificate-verified DNS-over-HTTPS only when the system resolver fails."""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import socket
import ssl
import threading
import time
import urllib.parse

_logger = logging.getLogger(__name__)
_DOH_IP = "8.8.8.8"
_DOH_HOST = "dns.google"
_DOH_TIMEOUT_SECONDS = 4
_CACHE_MAX_TTL_SECONDS = 300
_cache: dict[tuple[str, str], tuple[float, tuple[str, ...]]] = {}
_cache_lock = threading.Lock()


def _normalise_public_hostname(host: object) -> str | None:
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii")
        except UnicodeDecodeError:
            return None
    if not isinstance(host, str):
        return None

    hostname = host.rstrip(".")
    if not hostname or "." not in hostname:
        return None
    if hostname.lower().endswith((".local", ".localhost", ".internal")):
        return None
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _query_doh(hostname: str, record_type: str) -> tuple[tuple[str, ...], int]:
    query = urllib.parse.urlencode({"name": hostname, "type": record_type})
    raw_socket = socket.create_connection(
        (_DOH_IP, 443), timeout=_DOH_TIMEOUT_SECONDS
    )
    tls_socket = None
    try:
        tls_socket = ssl.create_default_context().wrap_socket(
            raw_socket, server_hostname=_DOH_HOST
        )
        request = (
            f"GET /resolve?{query} HTTP/1.1\r\n"
            f"Host: {_DOH_HOST}\r\n"
            "Accept: application/dns-json\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        tls_socket.sendall(request)

        response = http.client.HTTPResponse(tls_socket)
        response.begin()
        if response.status != 200:
            raise OSError(f"DNS-over-HTTPS returned HTTP {response.status}")
        payload = json.loads(response.read(65536))
        if payload.get("Status") != 0:
            return (), 0

        expected_type = 1 if record_type == "A" else 28
        addresses: list[str] = []
        ttls: list[int] = []
        for answer in payload.get("Answer", ()):
            if answer.get("type") != expected_type:
                continue
            try:
                address = ipaddress.ip_address(answer["data"])
            except (KeyError, ValueError):
                continue
            if (record_type == "A" and address.version == 4) or (
                record_type == "AAAA" and address.version == 6
            ):
                addresses.append(str(address))
                try:
                    ttls.append(int(answer.get("TTL", 60)))
                except (TypeError, ValueError):
                    ttls.append(60)

        ttl = min(ttls) if ttls else 0
        return tuple(dict.fromkeys(addresses)), ttl
    finally:
        if tls_socket is not None:
            tls_socket.close()
        else:
            raw_socket.close()


def _resolve_with_doh(hostname: str, record_type: str) -> tuple[str, ...]:
    key = (hostname, record_type)
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(key)
        if cached and cached[0] > now:
            return cached[1]

    addresses, ttl = _query_doh(hostname, record_type)
    if addresses and ttl > 0:
        expires_at = time.monotonic() + min(ttl, _CACHE_MAX_TTL_SECONDS)
        with _cache_lock:
            _cache[key] = (expires_at, addresses)
    return addresses


def install_dns_fallback() -> None:
    """Patch getaddrinfo with a public-hostname fallback after system DNS fails."""
    current_getaddrinfo = socket.getaddrinfo
    if getattr(current_getaddrinfo, "_dns_fallback_installed", False):
        return

    original_getaddrinfo = current_getaddrinfo

    def getaddrinfo_with_doh(
        host,
        port,
        family=0,
        type=0,
        proto=0,
        flags=0,
    ):
        try:
            return original_getaddrinfo(host, port, family, type, proto, flags)
        except socket.gaierror as resolver_error:
            if flags & getattr(socket, "AI_NUMERICHOST", 0):
                raise

            hostname = _normalise_public_hostname(host)
            if not hostname:
                raise

            if family == socket.AF_INET6:
                record_type, address_family = "AAAA", socket.AF_INET6
            elif family in (0, socket.AF_UNSPEC, socket.AF_INET):
                record_type, address_family = "A", socket.AF_INET
            else:
                raise

            try:
                addresses = _resolve_with_doh(hostname, record_type)
                results = []
                for address in addresses:
                    results.extend(
                        original_getaddrinfo(
                            address,
                            port,
                            address_family,
                            type,
                            proto,
                            flags,
                        )
                    )
                if results:
                    return results
            except Exception as fallback_error:
                _logger.warning(
                    "DNS-over-HTTPS fallback failed (%s)",
                    fallback_error.__class__.__name__,
                )

            raise resolver_error

    getaddrinfo_with_doh._dns_fallback_installed = True
    socket.getaddrinfo = getaddrinfo_with_doh
    _logger.info("System DNS fallback enabled for public hostnames")
