"""
SentinelScope Indicator of Compromise (IOC) Detection & Normalization Module.

Provides:
- Strict regex-based classification: 'ip', 'domain', 'url', 'hash', or 'invalid'
- RFC1918 and loopback IP rejection (HTTP 400)
- Bidirectional defanging and refanging utilities
"""

import ipaddress
import re
from typing import Tuple
from urllib.parse import urlparse
from fastapi import HTTPException, status

# Pre-compiled regex patterns
# Hashes: MD5 (32 hex characters) and SHA256 (64 hex characters)
HASH_MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
HASH_SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

# IPv4 Regex: exactly 4 octets between 0 and 255
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# Domain Regex (RFC 1035 compliant FQDN)
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$"
)

# URL Regex: requires http/https/ftp scheme or standard path structure
URL_SCHEME_PATTERN = re.compile(
    r"^(?:https?|ftp)://[^\s/$.?#].[^\s]*$", re.IGNORECASE
)

# RFC1918 Private and Loopback Subnets
RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def refang_ioc(raw_ioc: str) -> str:
    """
    Normalizes a defanged IOC string into a standard queryable format.
    E.g.:
      - 'hxxps://evil[.]com/path' -> 'https://evil.com/path'
      - '1.1.1[.]1' -> '1.1.1.1'
      - 'example[.]com' -> 'example.com'
    """
    if not raw_ioc:
        return ""
    
    cleaned = raw_ioc.strip()

    # Normalize schemes
    cleaned = re.sub(r"^hxxps://", "https://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^hxxp://", "http://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^fxp://", "ftp://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\[:\]", ":", cleaned)
    cleaned = re.sub(r"\(:/\)", "://", cleaned)

    # Normalize dot defangings: [.], (.), {.}, [dot]
    cleaned = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", ".", cleaned, flags=re.IGNORECASE)

    return cleaned


def defang_ioc(ioc: str, ioc_type: str = "") -> str:
    """
    Converts a potentially dangerous IOC into a safe defanged representation.
    E.g.:
      - 'http://test.com' -> 'hxxp://test[.]com'
      - 'https://test.com/path' -> 'hxxps://test[.]com/path'
      - '1.1.1.1' -> '1.1.1[.]1'
      - 'example.com' -> 'example[.]com'
      - Hashes remain unchanged.
    """
    if not ioc:
        return ioc
    
    clean = ioc.strip()

    if ioc_type == "hash" or HASH_MD5_PATTERN.match(clean) or HASH_SHA256_PATTERN.match(clean):
        return clean

    # Scheme defanging
    if clean.lower().startswith("https://"):
        clean = "hxxps://" + clean[8:]
    elif clean.lower().startswith("http://"):
        clean = "hxxp://" + clean[7:]
    elif clean.lower().startswith("ftp://"):
        clean = "fxp://" + clean[6:]

    # For URLs with scheme, defang host part only to keep path readable
    if "://" in clean:
        scheme, rest = clean.split("://", 1)
        if "/" in rest:
            host, path = rest.split("/", 1)
            if "." in host:
                host_parts = host.rsplit(".", 1)
                host = f"{host_parts[0]}[.]{host_parts[1]}"
            return f"{scheme}://{host}/{path}"
        else:
            if "." in rest:
                rest_parts = rest.rsplit(".", 1)
                rest = f"{rest_parts[0]}[.]{rest_parts[1]}"
            return f"{scheme}://{rest}"

    # For IPs or Domains, defang the last dot
    if "." in clean:
        parts = clean.rsplit(".", 1)
        return f"{parts[0]}[.]{parts[1]}"

    return clean


def validate_and_classify_ioc(raw_ioc: str) -> Tuple[str, str, str]:
    """
    Validates, refangs, and classifies the IOC into exactly:
    'ip', 'domain', 'url', 'hash', or raises HTTPException for private IPs / returns 'invalid'.

    Returns:
        (ioc_type, refanged_ioc, defanged_ioc)
    """
    if not raw_ioc or not isinstance(raw_ioc, str):
        return "invalid", "", ""

    trimmed = raw_ioc.strip()
    if not trimmed:
        return "invalid", "", ""

    # Normalize any existing defanging
    normalized = refang_ioc(trimmed)

    # 1. Check Hash (MD5 / SHA256)
    if HASH_MD5_PATTERN.match(normalized) or HASH_SHA256_PATTERN.match(normalized):
        return "hash", normalized.lower(), normalized.lower()

    # 2. Check IPv4
    if IPV4_PATTERN.match(normalized):
        try:
            ip_obj = ipaddress.IPv4Address(normalized)
            # Strict rejection of RFC1918 & loopback IPs
            for net in RFC1918_NETWORKS:
                if ip_obj in net:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            f"Private/RFC1918 or Loopback IP ({normalized}) is restricted. "
                            "External threat intelligence cannot evaluate internal/private network space."
                        ),
                    )

            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Non-routable or reserved IP ({normalized}) cannot be queried.",
                )

            return "ip", normalized, defang_ioc(normalized, "ip")
        except ipaddress.AddressValueError:
            return "invalid", normalized, trimmed

    # 3. Check URL
    # Case A: Explicit scheme
    if URL_SCHEME_PATTERN.match(normalized):
        parsed = urlparse(normalized)
        if parsed.netloc:
            # Check if URL host is a private IP
            host_only = parsed.netloc.split(":")[0]
            if IPV4_PATTERN.match(host_only):
                ip_obj = ipaddress.IPv4Address(host_only)
                for net in RFC1918_NETWORKS:
                    if ip_obj in net:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"URL host contains private/RFC1918 IP ({host_only}). Query rejected.",
                        )
            return "url", normalized, defang_ioc(normalized, "url")

    # Case B: URL without protocol but with path/query
    if "/" in normalized and not normalized.startswith("/"):
        candidate_url = f"http://{normalized}"
        if URL_SCHEME_PATTERN.match(candidate_url):
            parsed = urlparse(candidate_url)
            host_only = parsed.netloc.split(":")[0]
            if DOMAIN_PATTERN.match(host_only) or IPV4_PATTERN.match(host_only):
                if IPV4_PATTERN.match(host_only):
                    ip_obj = ipaddress.IPv4Address(host_only)
                    for net in RFC1918_NETWORKS:
                        if ip_obj in net:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"URL host contains private/RFC1918 IP ({host_only}). Query rejected.",
                            )
                return "url", candidate_url, defang_ioc(candidate_url, "url")

    # 4. Check Domain
    if DOMAIN_PATTERN.match(normalized):
        return "domain", normalized.lower(), defang_ioc(normalized.lower(), "domain")

    return "invalid", normalized, trimmed
