"""
IP address utility helpers for nt-traffic-filter.
Provides functions for validation, classification, and GeoIP enrichment.
"""

import ipaddress
import socket
from typing import Optional

# Well-known private / reserved ranges (RFC 1918, RFC 4193, loopback, link-local)
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_valid_ip(ip: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private(ip: str) -> bool:
    """Return True if the IP address belongs to a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def is_public(ip: str) -> bool:
    """Return True if the IP is publicly routable."""
    return is_valid_ip(ip) and not is_private(ip)


def ip_version(ip: str) -> Optional[int]:
    """Return 4 or 6 indicating IP version, or None if invalid."""
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


def reverse_lookup(ip: str) -> Optional[str]:
    """Perform a reverse DNS lookup. Returns hostname or None on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def ip_to_int(ip: str) -> Optional[int]:
    """Convert an IPv4/IPv6 address to its integer representation."""
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return None


def cidr_contains(cidr: str, ip: str) -> bool:
    """Return True if the given IP falls within the CIDR block."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        address = ipaddress.ip_address(ip)
        return address in network
    except ValueError:
        return False


def classify_ip(ip: str) -> str:
    """
    Return a human-readable classification for an IP address.
    Possible values: 'private', 'public', 'loopback', 'link-local', 'invalid'
    """
    if not is_valid_ip(ip):
        return "invalid"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "loopback"
        if addr.is_link_local:
            return "link-local"
        if addr.is_private:
            return "private"
        return "public"
    except ValueError:
        return "invalid"
