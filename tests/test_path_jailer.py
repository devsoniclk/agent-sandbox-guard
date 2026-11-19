"""Unit tests for PathJailer filesystem containment."""

import os
import tempfile
import pytest
from agent_sandbox_guard.path_jailer import PathJailer
from agent_sandbox_guard.types import PathAccessMode, SandboxPolicy, ViolationSeverity


def test_canonicalize_null_byte():
    with pytest.raises(ValueError):
        PathJailer.canonicalize("test\x00path")


def test_canonicalize_empty():
    with pytest.raises(ValueError):
        PathJailer.canonicalize("")


def test_canonicalize_valid():
    res = PathJailer.canonicalize("./test")
    assert os.path.isabs(res)


def test_is_contained_in_root():
    with tempfile.TemporaryDirectory() as tmpdir:
        sub = os.path.join(tmpdir, "child", "grandchild")
        os.makedirs(sub, exist_ok=True)
        assert PathJailer.is_contained_in_root(sub, tmpdir) is True
        assert PathJailer.is_contained_in_root("/etc", tmpdir) is False


def test_forbidden_paths():
    policy = SandboxPolicy()
    violations = PathJailer.check_forbidden_paths("/etc/shadow", policy)
    assert any(v.category == "FORBIDDEN_PATH_ACCESS" for v in violations)


def test_sensitive_credential_files():
    policy = SandboxPolicy()
    violations = PathJailer.check_forbidden_paths("/tmp/workspace/.env", policy)
    assert any(v.category == "SENSITIVE_CREDENTIAL_FILE" for v in violations)


def test_validate_access_inside_allowed_root():
    with tempfile.TemporaryDirectory() as tmpdir:
        policy = SandboxPolicy(
            allowed_read_roots=[tmpdir],
            allowed_write_roots=[tmpdir],
        )
        safe_file = os.path.join(tmpdir, "valid.txt")
        is_safe, canonical, violations = PathJailer.is_safe_read(safe_file, policy)
        assert is_safe is True
        assert len(violations) == 0

        is_safe, canonical, violations = PathJailer.is_safe_write(safe_file, policy)
        assert is_safe is True
        assert len(violations) == 0


def test_validate_access_outside_allowed_root():
    with tempfile.TemporaryDirectory() as tmpdir:
        policy = SandboxPolicy(
            allowed_read_roots=[tmpdir],
            allowed_write_roots=[tmpdir],
        )
        outside_file = "/var/log/system.log"
        is_safe, canonical, violations = PathJailer.is_safe_read(outside_file, policy)
        assert is_safe is False
        assert any(v.category == "SANDBOX_ESCAPE_ATTEMPT" for v in violations)


def test_symlink_directory_escape():
    with tempfile.TemporaryDirectory() as sandbox_dir:
        with tempfile.TemporaryDirectory() as target_dir:
            secret_file = os.path.join(target_dir, "secret.key")
            with open(secret_file, "w") as f:
                f.write("topsecret")

            symlink_path = os.path.join(sandbox_dir, "link_to_target")
            os.symlink(target_dir, symlink_path)

            policy = SandboxPolicy(
                allowed_read_roots=[sandbox_dir],
            )

            # Accessing through symlink should resolve to outside target_dir and be blocked
            attempted_path = os.path.join(symlink_path, "secret.key")
            is_safe, canonical, violations = PathJailer.is_safe_read(attempted_path, policy)
            assert is_safe is False
            assert any(v.category == "SANDBOX_ESCAPE_ATTEMPT" for v in violations)
