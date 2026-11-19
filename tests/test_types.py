"""Unit tests for types and schemas."""

import time
import pytest
from agent_sandbox_guard.types import (
    AuditRecord,
    PathAccessMode,
    SandboxPolicy,
    SanitizedOutput,
    SecurityViolation,
    ToolCallVerdict,
    ViolationSeverity,
)


def test_violation_severity_enum():
    assert ViolationSeverity.INFO.value == "INFO"
    assert ViolationSeverity.LOW.value == "LOW"
    assert ViolationSeverity.MEDIUM.value == "MEDIUM"
    assert ViolationSeverity.HIGH.value == "HIGH"
    assert ViolationSeverity.CRITICAL.value == "CRITICAL"


def test_path_access_mode_enum():
    assert PathAccessMode.READ.value == "READ"
    assert PathAccessMode.WRITE.value == "WRITE"
    assert PathAccessMode.DELETE.value == "DELETE"
    assert PathAccessMode.EXECUTE.value == "EXECUTE"
    assert PathAccessMode.MKDIR.value == "MKDIR"


def test_security_violation_to_dict():
    v = SecurityViolation(
        category="PATH_TRAVERSAL",
        severity=ViolationSeverity.CRITICAL,
        message="Escape attempt detected",
        target="/etc/passwd",
        metadata={"user": "agent"},
    )
    d = v.to_dict()
    assert d["category"] == "PATH_TRAVERSAL"
    assert d["severity"] == "CRITICAL"
    assert d["message"] == "Escape attempt detected"
    assert d["target"] == "/etc/passwd"
    assert d["mitigated"] is True
    assert d["metadata"]["user"] == "agent"


def test_sandbox_policy_defaults():
    policy = SandboxPolicy()
    assert policy.allow_subprocesses is True
    assert policy.allow_network is False
    assert policy.sanitize_environment is True
    assert policy.strip_markdown_beacons is True
    assert policy.detect_indirect_injection is True
    assert policy.enforce_circuit_breaker is True
    assert "sudo" in policy.forbidden_commands
    assert "/etc/shadow" in policy.forbidden_paths

    d = policy.to_dict()
    assert d["allow_subprocesses"] is True
    assert d["allow_network"] is False


def test_sanitized_output_serialization():
    out = SanitizedOutput(
        is_safe=True,
        original_length=100,
        cleaned_length=80,
        cleaned_text="Harmless text",
        beacons_removed=["https://tracker.com/img.png"],
        injection_alerts=[],
        risk_score=0.2,
    )
    d = out.to_dict()
    assert d["is_safe"] is True
    assert d["cleaned_text"] == "Harmless text"
    assert len(d["beacons_removed"]) == 1
