"""Network utility functions for parsing, validation, and security checking."""

import ipaddress
import re
from collections.abc import Sequence

from reconforge.core.exceptions import InvalidPortError, InvalidTargetError

# Cloud metadata addresses to guard against SSRF
CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # AWS, GCP, Azure, OpenStack, DigitalOcean
    ipaddress.ip_address("169.254.169.123"),  # AWS NTP
    ipaddress.ip_address("169.254.169.250"),  # Oracle Cloud
    ipaddress.ip_address("169.254.169.251"),  # Oracle Cloud
    ipaddress.ip_address("169.254.169.249"),  # Alibaba Cloud
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud DNS
    ipaddress.ip_address("fd00:ec2::254"),  # AWS IPv6 IMDSv2
}


def parse_ports(spec: str | Sequence[int | str]) -> list[int]:
    """Parse and validate port specifications.

    Accepts:
        - "80"
        - "80,443,8080"
        - "1-1024"
        - "22,80-90,443"
        - [80, 443, "8080-8085"]

    Returns:
        Sorted unique list of valid port integers (1-65535).

    Raises:
        InvalidPortError: If any port is outside 1-65535 or format is invalid.
    """
    if isinstance(spec, str):
        chunks = [c.strip() for c in spec.split(",") if c.strip()]
    elif isinstance(spec, Sequence):
        chunks = [str(item).strip() for item in spec if str(item).strip()]
    else:
        raise InvalidPortError(f"Unsupported port specification type: {type(spec)}")

    if not chunks:
        raise InvalidPortError("No ports specified.")

    parsed: set[int] = set()
    for chunk in chunks:
        if "-" in chunk:
            parts = chunk.split("-")
            if len(parts) != 2:
                raise InvalidPortError(f"Malformed port range: '{chunk}'")
            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError as err:
                raise InvalidPortError(f"Non-numeric values in port range: '{chunk}'") from err
            if start > end:
                raise InvalidPortError(f"Port range start ({start}) exceeds end ({end})")
            if start < 1 or end > 65535:
                raise InvalidPortError(f"Port range {start}-{end} outside legal bounds (1-65535)")
            parsed.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as err:
                raise InvalidPortError(f"Non-numeric port: '{chunk}'") from err
            if port < 1 or port > 65535:
                raise InvalidPortError(f"Port {port} outside legal bounds (1-65535)")
            parsed.add(port)

    return sorted(parsed)


def parse_ip_or_network(
    target: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse a string into an IP address or network (CIDR).

    Raises:
        InvalidTargetError: If target cannot be parsed as valid IP or CIDR.
    """
    target = target.strip()
    if "/" in target:
        try:
            return ipaddress.ip_network(target, strict=False)
        except ValueError as err:
            raise InvalidTargetError(f"Invalid CIDR specification '{target}': {err}") from err
    else:
        try:
            return ipaddress.ip_address(target)
        except ValueError as err:
            raise InvalidTargetError(f"Invalid IP address specification '{target}': {err}") from err


def is_valid_hostname(hostname: str) -> bool:
    """Check whether a string matches RFC 1123 DNS hostname rules."""
    if not hostname or len(hostname) > 253:
        return False
    if hostname.endswith("."):
        hostname = hostname[:-1]
    allowed = re.compile(r"^(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def is_cloud_metadata(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP address belongs to known cloud provider instance metadata services."""
    if isinstance(ip, str):
        try:
            ip = ipaddress.ip_address(ip)
        except ValueError:
            return False
    return ip in CLOUD_METADATA_IPS
