"""Secure forward DNS resolution with strict scope validation and IP pinning."""

import asyncio
import ipaddress
import socket

from reconforge.core.enums import AddressFamily
from reconforge.core.exceptions import DNSResolutionError, ScopeViolationError
from reconforge.core.models import ScanTarget
from reconforge.core.scope import ScopeManager


class DNSResolver:
    """
    DNS resolution engine designed to prevent DNS rebinding (TOCTOU) and scope bypasses.

    Principles:
    1. Hostname is validated against scope allowlist before resolution.
    2. Forward resolution retrieves all A and AAAA records.
    3. Every resolved IP address is validated against the scope allowlist.
    4. Out-of-scope resolutions are rejected immediately.
    5. The resolved IP is pinned to the target. Scanners connect directly to the pinned IP.
    """

    def __init__(self, scope_manager: ScopeManager, timeout_seconds: float = 5.0):
        self.scope_manager = scope_manager
        self.timeout_seconds = timeout_seconds

    async def resolve_hostname(self, hostname: str) -> list[ScanTarget]:
        """
        Resolve a hostname to pinned ScanTarget objects.

        Raises:
            ScopeViolationError: If hostname or any resolved IP is out-of-scope.
            DNSResolutionError: If DNS lookup fails or times out.
        """
        cleaned = hostname.strip().lower()
        if not self.scope_manager.is_hostname_allowed(cleaned):
            raise ScopeViolationError(
                f"Hostname '{cleaned}' is not authorized in assessment scope."
            )

        loop = asyncio.get_running_loop()
        try:
            # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(cleaned, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
                timeout=self.timeout_seconds,
            )
        except TimeoutError as err:
            raise DNSResolutionError(
                f"DNS resolution for '{cleaned}' timed out after {self.timeout_seconds}s."
            ) from err
        except socket.gaierror as err:
            raise DNSResolutionError(f"DNS lookup failed for '{cleaned}': {err.strerror}") from err
        except Exception as err:
            raise DNSResolutionError(f"Unexpected DNS error for '{cleaned}': {err}") from err

        pinned_targets: list[ScanTarget] = []
        seen_ips: set[str] = set()

        for _family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if ip_str in seen_ips:
                continue
            seen_ips.add(ip_str)

            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError as err:
                raise DNSResolutionError(
                    f"Invalid IP address '{ip_str}' returned for '{cleaned}': {err}"
                ) from err

            # Rebind / Scope Guard: Every resolved IP MUST independently satisfy the scope allowlist!
            if not self.scope_manager.is_ip_allowed(ip_obj):
                raise ScopeViolationError(
                    f"DNS Rebinding / Scope Violation: Hostname '{cleaned}' resolved to IP '{ip_str}', "
                    f"which is outside the authorized assessment scope."
                )

            addr_family = (
                AddressFamily.IPV4
                if isinstance(ip_obj, ipaddress.IPv4Address)
                else AddressFamily.IPV6
            )
            pinned_targets.append(
                ScanTarget(
                    ip=ip_str,
                    hostname=cleaned,
                    address_family=addr_family,
                    is_pinned=True,
                )
            )

        if not pinned_targets:
            raise DNSResolutionError(f"No valid IP addresses returned for hostname '{cleaned}'.")

        return pinned_targets

    async def resolve_all_scoped_hostnames(self) -> list[ScanTarget]:
        """Resolve all hostnames authorized in the ScopeManager."""
        all_targets: list[ScanTarget] = []
        for hostname in sorted(self.scope_manager.allowed_hostnames):
            resolved = await self.resolve_hostname(hostname)
            all_targets.extend(resolved)
        return all_targets
