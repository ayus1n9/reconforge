"""Scope authorization and boundary enforcement engine."""

import ipaddress

from reconforge.core.enums import AddressFamily
from reconforge.core.exceptions import (
    InvalidTargetError,
    ScopeViolationError,
)
from reconforge.core.models import ScanTarget, TargetScope
from reconforge.utils.network import (
    is_cloud_metadata,
    is_valid_hostname,
    parse_ip_or_network,
    parse_ports,
)

MAX_EXPANDED_CIDR_HOSTS = 4096


class ScopeManager:
    """
    Strict allowlist-based authorization boundary manager.

    Guarantees:
    - Never scans targets outside explicitly approved allowlists.
    - Exclusions always take precedence over allow rules.
    - Prevents accidental scanning of public internet unless explicitly permitted.
    - Prevents SSRF to cloud instance metadata (169.254.169.254, etc.).
    - Strict port boundary enforcement.
    """

    def __init__(self, scope: TargetScope):
        self.scope = scope
        self.allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.allowed_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self.allowed_hostnames: set[str] = set()

        self.excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.excluded_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self.excluded_hostnames: set[str] = set()

        self.allowed_ports: set[int] = set(parse_ports(scope.allowed_ports))

        self._compile_scope()

    def _compile_scope(self) -> None:
        """Parse and compile all target strings into IP/CIDR/hostname structures."""
        for target in self.scope.allowed_targets:
            self._add_target(
                target,
                self.allowed_networks,
                self.allowed_ips,
                self.allowed_hostnames,
            )

        for target in self.scope.excluded_targets:
            self._add_target(
                target,
                self.excluded_networks,
                self.excluded_ips,
                self.excluded_hostnames,
            )

    def _add_target(
        self,
        target_str: str,
        net_list: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
        ip_set: set[ipaddress.IPv4Address | ipaddress.IPv6Address],
        host_set: set[str],
    ) -> None:
        target_str = target_str.strip()
        if not target_str:
            return

        try:
            parsed = parse_ip_or_network(target_str)
            if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                # If it's a single host CIDR (e.g. /32 or /128), store as IP
                if parsed.num_addresses == 1:
                    ip_set.add(parsed.network_address)
                else:
                    net_list.append(parsed)
            else:
                ip_set.add(parsed)
            return
        except InvalidTargetError:
            pass

        # Check if valid hostname
        if is_valid_hostname(target_str):
            host_set.add(target_str.lower())
        else:
            raise InvalidTargetError(
                f"Target '{target_str}' is neither a valid IP, CIDR, nor hostname."
            )

    def is_ip_allowed(self, ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """
        Verify if an IP address is within authorized scope.

        Evaluates exclusions, cloud metadata protection, public internet constraints,
        and allowlists.
        """
        if isinstance(ip, str):
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                return False
        else:
            ip_obj = ip

        # 1. Cloud metadata guard (SSRF protection)
        if not self.scope.allow_cloud_metadata and is_cloud_metadata(ip_obj):
            return False

        # 2. Public Internet guard
        if not self.scope.allow_public_targets and ip_obj.is_global:
            return False

        # 3. Explicit exclusions take precedence
        if ip_obj in self.excluded_ips:
            return False
        for ex_net in self.excluded_networks:
            if ip_obj in ex_net:
                return False

        # 4. Explicit allow checks
        if ip_obj in self.allowed_ips:
            return True
        for allow_net in self.allowed_networks:
            if ip_obj in allow_net:
                return True

        return False

    def is_port_allowed(self, port: int) -> bool:
        """Check whether a port is within the authorized scope."""
        return port in self.allowed_ports

    def is_hostname_allowed(self, hostname: str) -> bool:
        """Check whether a hostname is explicitly allowed."""
        cleaned = hostname.strip().lower()
        if cleaned in self.excluded_hostnames:
            return False
        return cleaned in self.allowed_hostnames

    def validate_target_and_port(
        self,
        ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
        port: int,
    ) -> None:
        """
        Validate both target IP and port.

        Raises:
            ScopeViolationError: If target or port is unauthorized.
        """
        if isinstance(ip, str):
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError as err:
                raise ScopeViolationError(
                    f"Target '{ip}' is not a valid IP address: {err}"
                ) from err
        else:
            ip_obj = ip

        if not self.is_ip_allowed(ip_obj):
            if is_cloud_metadata(ip_obj) and not self.scope.allow_cloud_metadata:
                raise ScopeViolationError(
                    f"Target IP {ip_obj} rejected: cloud metadata endpoints are forbidden."
                )
            if ip_obj.is_global and not self.scope.allow_public_targets:
                raise ScopeViolationError(
                    f"Target IP {ip_obj} rejected: public internet scanning is not authorized."
                )
            raise ScopeViolationError(
                f"Target IP {ip_obj} is outside the approved assessment scope."
            )

        if not self.is_port_allowed(port):
            raise ScopeViolationError(f"Port {port} is outside the approved assessment port range.")

    def expand_static_targets(self) -> list[ScanTarget]:
        """
        Expand all static IP addresses and CIDR networks into individual ScanTargets.

        Protects against memory exhaustion by enforcing MAX_EXPANDED_CIDR_HOSTS.
        Does not resolve hostnames (DNSResolver handles that with pinning).
        """
        targets: list[ScanTarget] = []
        seen_ips: set[str] = set()

        # Add single IPs
        for ip_obj in sorted(self.allowed_ips, key=lambda x: int(x)):
            if self.is_ip_allowed(ip_obj):
                ip_str = str(ip_obj)
                if ip_str not in seen_ips:
                    seen_ips.add(ip_str)
                    family = (
                        AddressFamily.IPV4
                        if isinstance(ip_obj, ipaddress.IPv4Address)
                        else AddressFamily.IPV6
                    )
                    targets.append(ScanTarget(ip=ip_str, address_family=family, is_pinned=True))

        # Add CIDR hosts
        for net in self.allowed_networks:
            num = net.num_addresses
            if num > MAX_EXPANDED_CIDR_HOSTS:
                raise ScopeViolationError(
                    f"CIDR {net} contains {num} addresses, exceeding safe single-scan limit of {MAX_EXPANDED_CIDR_HOSTS}. "
                    f"Please define a smaller subnet (e.g., /24) to prevent resource exhaustion."
                )

            # For IPv4, use net.hosts() to skip network & broadcast if /30 or larger
            if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 30:
                host_iter = net.hosts()
            else:
                host_iter = net

            for ip_obj in host_iter:
                if self.is_ip_allowed(ip_obj):
                    ip_str = str(ip_obj)
                    if ip_str not in seen_ips:
                        seen_ips.add(ip_str)
                        family = (
                            AddressFamily.IPV4
                            if isinstance(ip_obj, ipaddress.IPv4Address)
                            else AddressFamily.IPV6
                        )
                        targets.append(ScanTarget(ip=ip_str, address_family=family, is_pinned=True))

        return targets
