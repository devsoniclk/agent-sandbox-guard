"""Unit tests for NetworkEgressEnforcer."""

import pytest
from agent_sandbox_guard.network_egress import NetworkEgressEnforcer
from agent_sandbox_guard.types import SandboxPolicy


def test_cloud_metadata_blocked():
    policy = SandboxPolicy(allow_network=True)
    is_safe, violations = NetworkEgressEnforcer.validate_destination("http://169.254.169.254/latest/meta-data", policy)
    assert is_safe is False
    assert any(v.category == "CLOUD_METADATA_SSRF_ATTEMPT" for v in violations)


def test_google_metadata_blocked():
    policy = SandboxPolicy(allow_network=True)
    is_safe, violations = NetworkEgressEnforcer.validate_destination("http://metadata.google.internal/computeMetadata/v1/", policy)
    assert is_safe is False
    assert any(v.category == "CLOUD_METADATA_SSRF_ATTEMPT" for v in violations)


def test_network_disabled_by_default():
    policy = SandboxPolicy(allow_network=False)
    is_safe, violations = NetworkEgressEnforcer.validate_destination("https://api.github.com", policy)
    assert is_safe is False
    assert any(v.category == "NETWORK_EGRESS_BLOCKED" for v in violations)


def test_private_ip_ssrf_blocked():
    policy = SandboxPolicy(allow_network=True)
    is_safe, violations = NetworkEgressEnforcer.validate_destination("http://10.0.0.5:8080/admin", policy)
    assert is_safe is False
    assert any(v.category == "INTERNAL_NETWORK_SSRF_DEFENSE" for v in violations)


def test_allowed_domains_whitelist():
    policy = SandboxPolicy(allow_network=True, allowed_domains=["api.github.com", "python.org"])
    is_safe, violations = NetworkEgressEnforcer.validate_destination("https://api.github.com/repos", policy)
    assert is_safe is True
    assert len(violations) == 0

    is_safe, violations = NetworkEgressEnforcer.validate_destination("https://evil.com/exfiltrate", policy)
    assert is_safe is False
    assert any(v.category == "DOMAIN_NOT_WHITELISTED" for v in violations)
