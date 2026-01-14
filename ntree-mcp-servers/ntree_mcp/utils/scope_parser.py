"""
Scope file parsing and IP validation
Ensures all pentest actions stay within authorized boundaries
"""

import ipaddress
import re
from typing import List, Set, Tuple
from pathlib import Path
from .logger import get_logger

logger = get_logger(__name__)


class ScopeValidator:
    """
    Parse and validate penetration test scope.

    Supports:
    - CIDR notation (192.168.1.0/24)
    - Individual IPs (192.168.1.50)
    - Domains (example.com)
    - Wildcard domains (*.internal.example.com)
    - Exclusions (EXCLUDE 192.168.1.1)
    """

    def __init__(self, scope_file: Path):
        """
        Initialize scope validator from file.

        Args:
            scope_file: Path to scope file

        Raises:
            FileNotFoundError: If scope file doesn't exist
            ValueError: If scope file is invalid
        """
        self.scope_file = Path(scope_file)

        if not self.scope_file.exists():
            raise FileNotFoundError(f"Scope file not found: {scope_file}")

        # Inclusion lists
        self.included_ranges: List[ipaddress.IPv4Network] = []
        self.included_ips: Set[ipaddress.IPv4Address] = set()
        self.included_domains: Set[str] = set()

        # Exclusion lists
        self.excluded_ranges: List[ipaddress.IPv4Network] = []
        self.excluded_ips: Set[ipaddress.IPv4Address] = set()

        self._parse_scope_file()

        # Validate we have at least some targets
        if not (self.included_ranges or self.included_ips or self.included_domains):
            raise ValueError("Scope file contains no valid targets")

        logger.info(f"Scope loaded: {self.get_scope_summary()}")

    def _parse_scope_file(self):
        """Parse scope file and populate inclusion/exclusion lists."""
        logger.debug(f"Parsing scope file: {self.scope_file}")

        with open(self.scope_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                try:
                    # Handle exclusions
                    if line.upper().startswith('EXCLUDE'):
                        # Remove 'EXCLUDE' prefix
                        target = line.split(maxsplit=1)[1] if len(line.split()) > 1 else ""
                        if target:
                            self._add_target(target, excluded=True)
                    else:
                        self._add_target(line, excluded=False)

                except Exception as e:
                    logger.warning(f"Line {line_num}: Error parsing '{line}': {e}")

    def _add_target(self, target: str, excluded: bool):
        """
        Add a target to included or excluded lists.

        Args:
            target: Target string (IP, CIDR, or domain)
            excluded: Whether this is an exclusion
        """
        target = target.strip()

        try:
            # Try parsing as network (CIDR notation)
            if '/' in target:
                network = ipaddress.IPv4Network(target, strict=False)
                if excluded:
                    self.excluded_ranges.append(network)
                    logger.debug(f"Added excluded range: {network}")
                else:
                    self.included_ranges.append(network)
                    logger.debug(f"Added included range: {network}")
                return

            # Try parsing as single IP
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                ip = ipaddress.IPv4Address(target)
                if excluded:
                    self.excluded_ips.add(ip)
                    logger.debug(f"Added excluded IP: {ip}")
                else:
                    self.included_ips.add(ip)
                    logger.debug(f"Added included IP: {ip}")
                return

            # Otherwise treat as domain
            # Basic domain validation
            if re.match(r'^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$', target):
                if not excluded:  # Domains can only be included, not excluded
                    self.included_domains.add(target.lower())
                    logger.debug(f"Added included domain: {target.lower()}")
                else:
                    logger.warning(f"Domain exclusions not supported, ignoring: {target}")
                return

            logger.warning(f"Invalid target format: {target}")

        except ValueError as e:
            logger.warning(f"Invalid target '{target}': {e}")

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is in scope.

        Args:
            target: IP address or domain to check

        Returns:
            Tuple of (in_scope: bool, reason: str)
        """
        # Try as IP address first
        try:
            ip = ipaddress.IPv4Address(target)
            return self._is_ip_in_scope(ip)
        except ValueError:
            pass

        # Try as domain
        return self._is_domain_in_scope(target)

    def _is_ip_in_scope(self, ip: ipaddress.IPv4Address) -> Tuple[bool, str]:
        """Check if an IP address is in scope."""
        # Check exclusions first (explicit denials take precedence)
        if ip in self.excluded_ips:
            return False, f"IP {ip} is explicitly excluded"

        for excluded_range in self.excluded_ranges:
            if ip in excluded_range:
                return False, f"IP {ip} is in excluded range {excluded_range}"

        # Check inclusions
        if ip in self.included_ips:
            return True, f"IP {ip} is explicitly included"

        for included_range in self.included_ranges:
            if ip in included_range:
                return True, f"IP {ip} is in included range {included_range}"

        # Not in any inclusion list
        return False, f"IP {ip} is not in any included scope"

    def _is_domain_in_scope(self, domain: str) -> Tuple[bool, str]:
        """Check if a domain is in scope."""
        domain = domain.lower()

        # Exact match
        if domain in self.included_domains:
            return True, f"Domain {domain} is explicitly included"

        # Wildcard match
        for scope_domain in self.included_domains:
            if scope_domain.startswith('*.'):
                # Extract base domain (everything after *.)
                base_domain = scope_domain[2:]

                # Check if target domain ends with base domain
                if domain.endswith(base_domain):
                    # Ensure it's actually a subdomain, not partial match
                    if domain == base_domain or domain.endswith('.' + base_domain):
                        return True, f"Domain {domain} matches wildcard {scope_domain}"

        return False, f"Domain {domain} is not in scope"

    def get_all_targets(self) -> List[str]:
        """
        Get all explicitly defined targets.

        Returns:
            List of target strings
        """
        targets = []
        targets.extend([str(ip) for ip in self.included_ips])
        targets.extend([str(net) for net in self.included_ranges])
        targets.extend(self.included_domains)
        return targets

    def get_scope_summary(self) -> dict:
        """
        Get a summary of the scope configuration.

        Returns:
            Dictionary with scope statistics
        """
        return {
            "included_ranges": len(self.included_ranges),
            "included_ips": len(self.included_ips),
            "included_domains": len(self.included_domains),
            "excluded_ranges": len(self.excluded_ranges),
            "excluded_ips": len(self.excluded_ips),
            "total_targets": len(self.get_all_targets()),
        }

    def validate_multiple(self, targets: List[str]) -> dict:
        """
        Validate multiple targets at once.

        Args:
            targets: List of targets to validate

        Returns:
            Dictionary with in_scope and out_of_scope lists
        """
        in_scope = []
        out_of_scope = []

        for target in targets:
            is_valid, reason = self.is_in_scope(target)
            if is_valid:
                in_scope.append({"target": target, "reason": reason})
            else:
                out_of_scope.append({"target": target, "reason": reason})

        return {
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "total_checked": len(targets),
        }

    def expand_ranges(self, max_hosts: int = 1000) -> List[str]:
        """
        Expand CIDR ranges to individual IPs.

        Args:
            max_hosts: Maximum number of hosts to expand (safety limit)

        Returns:
            List of IP addresses

        Raises:
            ValueError: If expansion would exceed max_hosts
        """
        ips = []

        # Add explicitly included IPs
        ips.extend([str(ip) for ip in self.included_ips])

        # Expand ranges
        total_hosts = sum(range.num_addresses for range in self.included_ranges)

        if total_hosts > max_hosts:
            raise ValueError(
                f"Range expansion would produce {total_hosts} hosts "
                f"(max: {max_hosts}). Use targeted scanning instead."
            )

        for network in self.included_ranges:
            for ip in network.hosts():
                # Skip if in exclusion list
                if ip in self.excluded_ips:
                    continue
                if any(ip in excluded_range for excluded_range in self.excluded_ranges):
                    continue

                ips.append(str(ip))

        return ips

    def __str__(self) -> str:
        """String representation of scope."""
        summary = self.get_scope_summary()
        return (
            f"ScopeValidator("
            f"{summary['included_ranges']} ranges, "
            f"{summary['included_ips']} IPs, "
            f"{summary['included_domains']} domains, "
            f"{summary['excluded_ips']} excluded IPs)"
        )
