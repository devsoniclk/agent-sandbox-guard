"""Path jailer and filesystem boundary enforcer for autonomous agents."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple

from agent_sandbox_guard.types import (
    PathAccessMode,
    SandboxPolicy,
    SecurityViolation,
    ViolationSeverity,
)


@lru_cache(maxsize=8192)
def _cached_canonicalize(raw_path: str) -> str:
    expanded = os.path.expanduser(os.path.expandvars(raw_path))
    return os.path.realpath(expanded)


class PathJailer:
    """Enforces strict path canonicalization and directory jail boundaries."""

    @staticmethod
    def canonicalize(raw_path: str) -> str:
        """Fully resolve symlinks, relative segments, environment variables, and home directory."""
        if not raw_path or "\x00" in raw_path:
            raise ValueError("Invalid path containing null bytes or empty string")

        return _cached_canonicalize(raw_path)

    @staticmethod
    def is_contained_in_root(target_path: str, root_path: str) -> bool:
        """Check if target_path is equal to or strictly a child of root_path."""
        target_canonical = PathJailer.canonicalize(target_path)
        root_canonical = PathJailer.canonicalize(root_path)

        # Exact match or child
        try:
            target_p = Path(target_canonical)
            root_p = Path(root_canonical)
            target_p.relative_to(root_p)
            return True
        except ValueError:
            return False

    @classmethod
    def check_forbidden_paths(
        cls, canonical_path: str, policy: SandboxPolicy
    ) -> List[SecurityViolation]:
        """Check if target canonical path intersects with any forbidden path pattern."""
        violations: List[SecurityViolation] = []

        for forbidden in policy.forbidden_paths:
            try:
                forbidden_canonical = cls.canonicalize(forbidden)
                # Check if target is inside forbidden directory or exact match
                if canonical_path == forbidden_canonical or cls.is_contained_in_root(
                    canonical_path, forbidden_canonical
                ):
                    violations.append(
                        SecurityViolation(
                            category="FORBIDDEN_PATH_ACCESS",
                            severity=ViolationSeverity.CRITICAL,
                            message=f"Access to sensitive path '{forbidden}' is strictly blocked",
                            target=canonical_path,
                            metadata={"forbidden_rule": forbidden},
                        )
                    )
            except Exception:
                continue

        # Sensitive filenames heuristic check
        sensitive_basenames = {
            ".env",
            "id_rsa",
            "id_ed25519",
            "credentials",
            "service-account.json",
            "master.key",
            "private.pem",
        }
        basename = os.path.basename(canonical_path)
        if basename in sensitive_basenames and not any(
            v.category == "FORBIDDEN_PATH_ACCESS" for v in violations
        ):
            violations.append(
                SecurityViolation(
                    category="SENSITIVE_CREDENTIAL_FILE",
                    severity=ViolationSeverity.HIGH,
                    message=f"Access to credential file '{basename}' is restricted",
                    target=canonical_path,
                )
            )

        return violations

    @classmethod
    def validate_access(
        cls,
        raw_path: str,
        mode: PathAccessMode,
        policy: SandboxPolicy,
    ) -> Tuple[bool, Optional[str], List[SecurityViolation]]:
        """Validate whether a file operation mode is permitted by policy."""
        try:
            canonical_path = cls.canonicalize(raw_path)
        except Exception as e:
            return (
                False,
                None,
                [
                    SecurityViolation(
                        category="MALFORMED_PATH",
                        severity=ViolationSeverity.CRITICAL,
                        message=f"Failed to resolve path: {str(e)}",
                        target=raw_path,
                    )
                ],
            )

        # 1. Check forbidden paths first
        forbidden_violations = cls.check_forbidden_paths(canonical_path, policy)
        if forbidden_violations:
            return False, canonical_path, forbidden_violations

        # 2. Check allowed roots
        allowed_roots = (
            policy.allowed_write_roots
            if mode in (PathAccessMode.WRITE, PathAccessMode.DELETE, PathAccessMode.MKDIR)
            else policy.allowed_read_roots
        )

        # If roots are defined, the target must fall inside at least one
        if allowed_roots:
            is_contained = any(
                cls.is_contained_in_root(canonical_path, root) for root in allowed_roots
            )
            if not is_contained:
                violation = SecurityViolation(
                    category="SANDBOX_ESCAPE_ATTEMPT",
                    severity=ViolationSeverity.CRITICAL,
                    message=(
                        f"Path '{canonical_path}' is outside authorized {mode.value.lower()} "
                        f"roots: {allowed_roots}"
                    ),
                    target=canonical_path,
                    metadata={"mode": mode.value, "allowed_roots": allowed_roots},
                )
                return False, canonical_path, [violation]

        return True, canonical_path, []

    @classmethod
    def is_safe_read(
        cls, raw_path: str, policy: SandboxPolicy
    ) -> Tuple[bool, Optional[str], List[SecurityViolation]]:
        """Convenience helper to audit a read operation."""
        return cls.validate_access(raw_path, PathAccessMode.READ, policy)

    @classmethod
    def is_safe_write(
        cls, raw_path: str, policy: SandboxPolicy
    ) -> Tuple[bool, Optional[str], List[SecurityViolation]]:
        """Convenience helper to audit a write operation."""
        return cls.validate_access(raw_path, PathAccessMode.WRITE, policy)

    @classmethod
    def is_safe_delete(
        cls, raw_path: str, policy: SandboxPolicy
    ) -> Tuple[bool, Optional[str], List[SecurityViolation]]:
        """Convenience helper to audit a delete operation."""
        return cls.validate_access(raw_path, PathAccessMode.DELETE, policy)
