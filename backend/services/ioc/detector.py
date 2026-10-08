"""IOC Detection and Sanitization Service.

Cleans defanged indicators (e.g. hxxp://, 1[.]1[.]1[.]1) and heuristically
classifies inputs into one of 7 supported IOC taxonomies:
- IPv4
- IPv6
- Domain
- URL
- MD5
- SHA-1
- SHA-256
"""

import re
from typing import Optional

# Regex definitions for taxonomy detection
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# RFC 4291 compliant IPv6 detection pattern
IPV6_PATTERN = re.compile(
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
    r"^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,7}:$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|"
    r"^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|"
    r"^:(?::[0-9a-fA-F]{1,4}){1,7}$|^::$"
)

MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

# Domain pattern (RFC 1035 / RFC 1123)
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)

# URL detection pattern
URL_PATTERN = re.compile(
    r"^https?://[^\s/$.?#].[^\s]*$",
    re.IGNORECASE
)


def sanitize_ioc(raw_ioc: str) -> str:
    """Sanitize and un-defang an IOC string.

    Examples:
        'hxxp://malicious[.]com' -> 'http://malicious.com'
        '1[.]1[.]1[.]1'          -> '1.1.1.1'
        '8.8.8.8:8080'           -> '8.8.8.8' (for bare IP analysis)
        '  EXAMPLE[.]COM  '      -> 'example.com'
    """
    if not raw_ioc:
        return ""

    sanitized = raw_ioc.strip()

    # Remove enclosing quotes or brackets: <http://...> -> http://...
    if (sanitized.startswith("<") and sanitized.endswith(">")) or \
       (sanitized.startswith('"') and sanitized.endswith('"')) or \
       (sanitized.startswith("'") and sanitized.endswith("'")):
        sanitized = sanitized[1:-1].strip()

    # Normalize defanged protocols
    sanitized = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group(0).lower() else "http://", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"^fxps?://", "ftp://", sanitized, flags=re.IGNORECASE)

    # Normalize defanged dots: [.] or (.) or {.} -> .
    sanitized = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", sanitized)

    # Normalize defanged colons: [:] or (:) -> :
    sanitized = re.sub(r"\[:\]|\(:\)", ":", sanitized)

    # If it is a domain without URL scheme, lowercase it
    if not (sanitized.startswith("http://") or sanitized.startswith("https://")):
        # If it's a hex hash, lowercase it
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", sanitized):
            sanitized = sanitized.lower()

    return sanitized


def detect_ioc_type(ioc: str) -> Optional[str]:
    """Heuristically identify the IOC type.

    Returns:
        One of 'IPv4', 'IPv6', 'MD5', 'SHA-1', 'SHA-256', 'URL', 'Domain', or None.
    """
    if not ioc:
        return None

    # 1. URL check (starts with http:// or https://)
    if URL_PATTERN.match(ioc):
        return "URL"

    # 2. IPv4 check
    if IPV4_PATTERN.match(ioc):
        return "IPv4"

    # 3. Hash checks (exact length and hex charset)
    if SHA256_PATTERN.match(ioc):
        return "SHA-256"
    if SHA1_PATTERN.match(ioc):
        return "SHA-1"
    if MD5_PATTERN.match(ioc):
        return "MD5"

    # 4. IPv6 check
    if ":" in ioc and IPV6_PATTERN.match(ioc):
        return "IPv6"

    # 5. Domain check
    if DOMAIN_PATTERN.match(ioc):
        return "Domain"

    return None
