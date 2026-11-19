"""Unit tests for master SandboxGuardEngine."""

import os
import tempfile
import pytest
from agent_sandbox_guard.engine import SandboxGuardEngine
from agent_sandbox_guard.types import SandboxPolicy, ViolationSeverity


def test_intercept_tool_call_read_file_safe():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "doc.txt")
        with open(test_file, "w") as f:
            f.write("test content")

        policy = SandboxPolicy(allowed_read_roots=[tmpdir])
        engine = SandboxGuardEngine(policy)

        verdict = engine.intercept_tool_call(
            tool_name="read_file",
            arguments={"path": test_file},
            agent_id="agent-007",
        )
        assert verdict.is_allowed is True
        assert verdict.operation == "FILE_READ"
        assert len(verdict.violations) == 0
        assert verdict.audit_id is not None


def test_intercept_tool_call_read_file_forbidden():
    policy = SandboxPolicy()
    engine = SandboxGuardEngine(policy)

    verdict = engine.intercept_tool_call(
        tool_name="read_file",
        arguments={"path": "/etc/shadow"},
        agent_id="agent-007",
    )
    assert verdict.is_allowed is False
    assert any(v.category == "FORBIDDEN_PATH_ACCESS" for v in verdict.violations)


def test_intercept_tool_call_forbidden_command():
    policy = SandboxPolicy()
    engine = SandboxGuardEngine(policy)

    verdict = engine.intercept_tool_call(
        tool_name="bash",
        arguments={"command": "sudo rm -rf /var/log"},
        agent_id="agent-007",
    )
    assert verdict.is_allowed is False
    assert any(v.category == "FORBIDDEN_BINARY_EXECUTION" for v in verdict.violations)


def test_intercept_tool_call_cloud_metadata():
    policy = SandboxPolicy(allow_network=True)
    engine = SandboxGuardEngine(policy)

    verdict = engine.intercept_tool_call(
        tool_name="fetch_url",
        arguments={"url": "http://169.254.169.254/latest/meta-data"},
        agent_id="agent-007",
    )
    assert verdict.is_allowed is False
    assert any(v.category == "CLOUD_METADATA_SSRF_ATTEMPT" for v in verdict.violations)


def test_circuit_breaker_tripping_and_reset():
    policy = SandboxPolicy(max_critical_violations=1)
    engine = SandboxGuardEngine(policy)
    assert engine.is_circuit_breaker_tripped is False

    # Trigger a critical violation
    engine.intercept_tool_call("bash", {"command": "sudo cat /etc/shadow"})
    assert engine.is_circuit_breaker_tripped is True

    # Any subsequent tool calls should be blocked by circuit breaker
    verdict2 = engine.intercept_tool_call("read_file", {"path": "/tmp/harmless.txt"})
    assert verdict2.is_allowed is False
    assert any(v.category == "CIRCUIT_BREAKER_ACTIVE" for v in verdict2.violations)

    # Reset circuit breaker
    engine.reset_circuit_breaker()
    assert engine.is_circuit_breaker_tripped is False


def test_safe_file_read_and_write():
    with tempfile.TemporaryDirectory() as tmpdir:
        policy = SandboxPolicy(
            allowed_read_roots=[tmpdir],
            allowed_write_roots=[tmpdir],
        )
        engine = SandboxGuardEngine(policy)

        target = os.path.join(tmpdir, "test.txt")
        success, violations = engine.safe_write_file(target, "hello world")
        assert success is True
        assert len(violations) == 0

        read_ok, content, read_violations = engine.safe_read_file(target)
        assert read_ok is True
        assert content == "hello world"
        assert len(read_violations) == 0


def test_safe_execute_command():
    policy = SandboxPolicy(allowed_commands=["python3"])
    engine = SandboxGuardEngine(policy)

    success, proc, violations = engine.safe_execute_command("python3 -c \"print('guarded')\"")
    assert success is True
    assert proc is not None
    assert proc.returncode == 0
    assert "guarded" in proc.stdout


def test_audit_summary():
    engine = SandboxGuardEngine()
    engine.intercept_tool_call("read_file", {"path": "/etc/shadow"})
    summary = engine.get_audit_summary()
    assert summary["total_actions_audited"] == 1
    assert summary["actions_blocked"] == 1
    assert summary["total_violations"] >= 1
    assert summary["ledger_integrity_verified"] is True
