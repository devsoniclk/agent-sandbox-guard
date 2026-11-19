"""Network egress firewall, SSRF defense, and cloud metadata shield."""

from __future__ import annotations

import ipaddress
import re
from typing import List, Tuple
from urllib.parse import urlparse

from agent_sandbox_guard.types import (
    SandboxPolicy,
    SecurityViolation,
    ViolationSeverity,
)


class NetworkEgressEnforcer:
    """Audits and restricts network egress, preventing data exfiltration and SSRF metadata abuse."""

    CLOUD_METADATA_HOSTS = {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.internal",
        "100.100.100.200",  # Alibaba Cloud
    }

    @classmethod
    def is_private_ip(cls, hostname: str) -> bool:
        """Check if hostname resolves to an RFC 1918 or loopback private IP address."""
        try:
            ip = ipaddress.ip_address(hostname)
            return (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            )
        except ValueError:
            return False

    @classmethod
    def validate_destination(
        cls,
        target_url_or_host: str,
        policy: SandboxPolicy,
    ) -> Tuple[bool, List[SecurityViolation]]:
        """Validate whether outbound network egress to target is permitted by policy."""
        violations: List[SecurityViolation] = []

        if not target_url_or_host:
            return True, []

        # Parse target as URL or raw host
        if "://" in target_url_or_host:
            parsed = urlparse(target_url_or_host)
            hostname = parsed.hostname or ""
            port = parsed.port
            scheme = parsed.scheme.lower()
        else:
            parts = target_url_or_host.split(":")
            hostname = parts[0]
            port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            scheme = "tcp"

        hostname_lower = hostname.lower()

        # 1. Cloud metadata service SSRF defense (CRITICAL)
        if hostname_lower in cls.CLOUD_METADATA_HOSTS or hostname_lower.endswith(".internal"):
            violations.append(
                SecurityViolation(
                    category="CLOUD_METADATA_SSRF_ATTEMPT",
                    severity=ViolationSeverity.CRITICAL,
                    message=f"Access to cloud metadata service '{hostname_lower}' is strictly blocked",
                    target=target_url_or_host,
                    metadata={"hostname": hostname_lower},
                )
            )
            return False, violations

        # 2. Global network disabled check
        if not policy.allow_network:
            violations.append(
                SecurityViolation(
                    category="NETWORK_EGRESS_BLOCKED",
                    severity=ViolationSeverity.HIGH,
                    message="Network egress is disabled by sandbox policy",
                    target=target_url_or_host,
                )
            )
            return False, violations

        # 3. Private IP access check (unless localhost explicitly allowed)
        if cls.is_private_ip(hostname_lower):
            if "localhost" not in policy.allowed_domains and "127.0.0.1" not in policy.allowed_domains:
                violations.append(
                    SecurityViolation(
                        category="INTERNAL_NETWORK_SSRF_DEFENSE",
                        severity=ViolationSeverity.CRITICAL,
                        message=f"Access to internal/private IP '{hostname_lower}' is prohibited",
                        target=target_url_or_host,
                    )
                )

        # 4. Domain allowlist check
        if policy.allowed_domains:
            matched = False
            for allowed in policy.allowed_domains:
                allowed_clean = allowed.lower().lstrip(".")
                if hostname_lower == allowed_clean or hostname_lower.endswith(f".{allowed_clean}"):
                    matched = True
                    break

            if not matched:
                violations.append(
                    SecurityViolation(
                        category="DOMAIN_NOT_WHITELISTED",
                        severity=ViolationSeverity.HIGH,
                        message=f"Host '{hostname_lower}' is not in allowed domains: {policy.allowed_domains}",
                        target=target_url_or_host,
                    )
                )

        is_allowed = len(violations) == 0
        return is_allowed, violations
