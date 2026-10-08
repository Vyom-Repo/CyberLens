"""IOC Validation and Routability Verification Service.

Performs strict structural validation on IOCs, enforces routability guards
(rejecting RFC 1918 private, loopback, link-local, and multicast addresses),
and resolves appropriate threat intelligence data sources.
"""

import ipaddress
import re
from typing import List, Optional
from urllib.parse import urlparse

from backend.services.ioc.detector import (
    DOMAIN_PATTERN,
    MD5_PATTERN,
    SHA1_PATTERN,
    SHA256_PATTERN,
    detect_ioc_type,
    sanitize_ioc,
)


class IOCValidationResult:
    """Encapsulates the outcome of an IOC validation check."""

    def __init__(
        self,
        valid: bool,
        sanitized_ioc: Optional[str] = None,
        ioc_type: Optional[str] = None,
        is_routable: bool = True,
        supported_sources: Optional[List[str]] = None,
        error: Optional[str] = None,
    ):
        self.valid = valid
        self.sanitized_ioc = sanitized_ioc
        self.ioc_type = ioc_type
        self.is_routable = is_routable
        self.supported_sources = supported_sources or []
        self.error = error

    def to_dict(self):
        return {
            "valid": self.valid,
            "sanitized_ioc": self.sanitized_ioc,
            "detected_type": self.ioc_type,
            "is_routable": self.is_routable,
            "supported_sources": self.supported_sources,
            "error": self.error,
        }


def _validate_ip_address(ip_str: str, expected_version: Optional[int] = None) -> IOCValidationResult:
    """Validate IPv4 or IPv6 address and ensure it is globally routable."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=ip_str,
            error=f"'{ip_str}' is not a syntactically valid IP address.",
        )

    if expected_version and ip_obj.version != expected_version:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=ip_str,
            error=f"Expected IPv{expected_version} address, but found IPv{ip_obj.version}.",
        )

    ioc_type = f"IPv{ip_obj.version}"

    # Routability & safety guards (check specific categories first)
    if ip_obj.is_loopback:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=ip_str,
            ioc_type=ioc_type,
            is_routable=False,
            error=f"The IP address {ip_str} is a loopback address (localhost) and cannot be queried.",
        )

    if ip_obj.is_private:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=ip_str,
            ioc_type=ioc_type,
            is_routable=False,
            error=(
                f"The IP address {ip_str} is an RFC 1918/RFC 4193 private address. "
                "Private network addresses cannot be queried against public threat intelligence feeds."
            ),
        )

    if ip_obj.is_link_local:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=ip_str,
            ioc_type=ioc_type,
            is_routable=False,
            error=f"The IP address {ip_str} is a non-routable link-local address.",
        )

    if ip_obj.is_multicast:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=ip_str,
            ioc_type=ioc_type,
            is_routable=False,
            error=f"The IP address {ip_str} is a multicast group address and cannot be queried.",
        )

    if ip_obj.is_reserved:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=ip_str,
            ioc_type=ioc_type,
            is_routable=False,
            error=f"The IP address {ip_str} is an IETF reserved address.",
        )

    return IOCValidationResult(
        valid=True,
        sanitized_ioc=str(ip_obj),
        ioc_type=ioc_type,
        is_routable=True,
        supported_sources=["virustotal", "abuseipdb"],
    )


def _validate_domain(domain_str: str) -> IOCValidationResult:
    """Validate fully qualified domain name structure."""
    clean_domain = domain_str.lower().rstrip(".")

    if not DOMAIN_PATTERN.match(clean_domain):
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=domain_str,
            ioc_type="Domain",
            error=f"'{domain_str}' is not a syntactically valid domain name.",
        )

    # Reject domains that end with numeric TLD (often accidental IPs)
    tld = clean_domain.split(".")[-1]
    if tld.isdigit():
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=domain_str,
            ioc_type="Domain",
            error=f"'{domain_str}' has an invalid numeric Top-Level Domain.",
        )

    return IOCValidationResult(
        valid=True,
        sanitized_ioc=clean_domain,
        ioc_type="Domain",
        is_routable=True,
        supported_sources=["virustotal"],
    )


def _validate_url(url_str: str) -> IOCValidationResult:
    """Validate web URL scheme, host, and path structure."""
    try:
        parsed = urlparse(url_str)
    except Exception:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=url_str,
            ioc_type="URL",
            error=f"Malformed URL string: '{url_str}'.",
        )

    if parsed.scheme.lower() not in ("http", "https"):
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=url_str,
            ioc_type="URL",
            error=f"Unsupported URL protocol '{parsed.scheme}'. Only HTTP and HTTPS are supported.",
        )

    hostname = parsed.hostname
    if not hostname:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=url_str,
            ioc_type="URL",
            error="URL must contain a valid host destination.",
        )

    # If the URL hostname is an IP, check if it's private
    try:
        ip_check = ipaddress.ip_address(hostname)
        if ip_check.is_private or ip_check.is_loopback:
            return IOCValidationResult(
                valid=False,
                sanitized_ioc=url_str,
                ioc_type="URL",
                is_routable=False,
                error=f"URL targets a private/local IP destination ({hostname}).",
            )
    except ValueError:
        # Hostname is a domain name, verify length
        if len(hostname) > 253:
            return IOCValidationResult(
                valid=False,
                sanitized_ioc=url_str,
                ioc_type="URL",
                error="URL hostname exceeds maximum domain length (253 characters).",
            )

    return IOCValidationResult(
        valid=True,
        sanitized_ioc=url_str,
        ioc_type="URL",
        is_routable=True,
        supported_sources=["virustotal"],
    )


def _validate_hash(hash_str: str, hash_type: str) -> IOCValidationResult:
    """Validate cryptographic digest character set and length."""
    clean_hash = hash_str.lower().strip()

    pattern_map = {
        "MD5": (MD5_PATTERN, 32),
        "SHA-1": (SHA1_PATTERN, 40),
        "SHA-256": (SHA256_PATTERN, 64),
    }

    if hash_type not in pattern_map:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=hash_str,
            error=f"Unsupported hash type '{hash_type}'.",
        )

    pattern, length = pattern_map[hash_type]
    if not pattern.match(clean_hash):
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=clean_hash,
            ioc_type=hash_type,
            error=f"Invalid {hash_type} hash format. Expected {length} hexadecimal characters.",
        )

    return IOCValidationResult(
        valid=True,
        sanitized_ioc=clean_hash,
        ioc_type=hash_type,
        is_routable=True,
        supported_sources=["virustotal"],
    )


def validate_ioc(raw_ioc: str, explicit_type: Optional[str] = None) -> IOCValidationResult:
    """Master validation pipeline: sanitizes, detects, validates, and resolves sources.

    Args:
        raw_ioc: Raw input string from analyst.
        explicit_type: Optional forced IOC classification override.

    Returns:
        IOCValidationResult with status, sanitized string, confirmed type, and source mappings.
    """
    if not raw_ioc or not raw_ioc.strip():
        return IOCValidationResult(
            valid=False,
            error="IOC input string cannot be empty.",
        )

    sanitized = sanitize_ioc(raw_ioc)
    target_type = explicit_type if explicit_type else detect_ioc_type(sanitized)

    if not target_type:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=sanitized,
            error=(
                f"Unable to recognize indicator type for '{sanitized}'. "
                "Supported formats: IPv4, IPv6, Domain, URL, MD5, SHA-1, SHA-256."
            ),
        )

    upper_type = target_type.upper()
    if upper_type == "IPV4":
        return _validate_ip_address(sanitized, expected_version=4)
    elif upper_type == "IPV6":
        return _validate_ip_address(sanitized, expected_version=6)
    elif upper_type == "DOMAIN":
        return _validate_domain(sanitized)
    elif upper_type == "URL":
        return _validate_url(sanitized)
    elif upper_type == "MD5":
        return _validate_hash(sanitized, "MD5")
    elif upper_type in ("SHA-1", "SHA1"):
        return _validate_hash(sanitized, "SHA-1")
    elif upper_type in ("SHA-256", "SHA256"):
        return _validate_hash(sanitized, "SHA-256")
    else:
        return IOCValidationResult(
            valid=False,
            sanitized_ioc=sanitized,
            error=f"Unsupported IOC type: '{target_type}'.",
        )
