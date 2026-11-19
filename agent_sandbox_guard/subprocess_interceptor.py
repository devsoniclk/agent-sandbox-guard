"""Subprocess command interceptor, reverse-shell analyzer, and environment sanitizer."""

from __future__ import annotations

import os
import re
import shlex
from typing import Dict, List, Optional, Sequence, Tuple, Union

from agent_sandbox_guard.types import (
    SandboxPolicy,
    SecurityViolation,
    ViolationSeverity,
)


class SubprocessInterceptor:
    """Audits shell and subprocess invocations to prevent privilege escalation and remote execution."""

    REVERSE_SHELL_PATTERNS = [
        re.compile(r"/dev/(?:tcp|udp)/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+", re.IGNORECASE),
        re.compile(r"nc(?:\.traditional)?\s+-[el].*\d+", re.IGNORECASE),
        re.compile(r"(?:bash|sh|zsh)\s+-i\s+>&", re.IGNORECASE),
        re.compile(r"mkfifo\s+.*(?:nc|telnet)", re.IGNORECASE),
        re.compile(r"python(?:\d)?\s+-c\s+.*socket\..*pty\.spawn", re.IGNORECASE),
        re.compile(r"perl\s+-e\s+.*use\s+Socket", re.IGNORECASE),
        re.compile(r"socat\s+exec:.*tcp-connect:", re.IGNORECASE),
    ]

    DESTRUCTIVE_PATTERNS = [
        re.compile(r"rm\s+-(?:r[fv]|f[rv]|rf)\s+(?:/|/\*|~|~/\*|\$HOME|\$HOME/\*)(\s+|$)", re.IGNORECASE),
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),  # fork bomb
        re.compile(r"dd\s+if=.*\s+of=/dev/[sh]d[a-z]", re.IGNORECASE),
        re.compile(r"mkfs(?:\.[a-z0-9]+)?\s+/dev/[sh]d[a-z]", re.IGNORECASE),
        re.compile(r">/dev/[sh]d[a-z]", re.IGNORECASE),
    ]

    @classmethod
    def tokenize(cls, command: Union[str, Sequence[str]]) -> List[str]:
        """Convert command input safely to tokenized argv list."""
        if isinstance(command, (list, tuple)):
            return [str(arg) for arg in command]

        if not isinstance(command, str) or not command.strip():
            return []

        # Safe shlex splitting
        try:
            return shlex.split(command)
        except ValueError as e:
            # Syntax error in command string (e.g. unclosed quote)
            raise ValueError(f"Malformed shell string: {str(e)}") from e

    @classmethod
    def audit_command(
        cls,
        command: Union[str, Sequence[str]],
        policy: SandboxPolicy,
    ) -> Tuple[bool, List[str], List[SecurityViolation]]:
        """Audit command tokens and detect disallowed binaries or shell payloads."""
        violations: List[SecurityViolation] = []

        if not policy.allow_subprocesses:
            violations.append(
                SecurityViolation(
                    category="SUBPROCESS_BLOCKED",
                    severity=ViolationSeverity.CRITICAL,
                    message="Subprocess execution is globally disabled by policy",
                    target=str(command),
                )
            )
            return False, [], violations

        cmd_str = command if isinstance(command, str) else " ".join(command)

        # 1. Reverse shell detection
        for pattern in cls.REVERSE_SHELL_PATTERNS:
            if pattern.search(cmd_str):
                violations.append(
                    SecurityViolation(
                        category="REVERSE_SHELL_DETECTED",
                        severity=ViolationSeverity.CRITICAL,
                        message=f"Interactive reverse shell pattern identified: {pattern.pattern}",
                        target=cmd_str,
                        metadata={"pattern": pattern.pattern},
                    )
                )

        # 2. Destructive command detection
        for pattern in cls.DESTRUCTIVE_PATTERNS:
            if pattern.search(cmd_str):
                violations.append(
                    SecurityViolation(
                        category="CATASTROPHIC_DESTRUCTION",
                        severity=ViolationSeverity.CRITICAL,
                        message="Catastrophic filesystem or system wipe command detected",
                        target=cmd_str,
                        metadata={"pattern": pattern.pattern},
                    )
                )

        # 3. Tokenize command
        try:
            tokens = cls.tokenize(command)
        except ValueError as err:
            violations.append(
                SecurityViolation(
                    category="MALFORMED_COMMAND",
                    severity=ViolationSeverity.HIGH,
                    message=str(err),
                    target=cmd_str,
                )
            )
            return False, [], violations

        if not tokens:
            return True, [], []

        executable = os.path.basename(tokens[0]).lower()

        # 4. Check forbidden commands
        if executable in policy.forbidden_commands:
            violations.append(
                SecurityViolation(
                    category="FORBIDDEN_BINARY_EXECUTION",
                    severity=ViolationSeverity.CRITICAL,
                    message=f"Executable '{executable}' is forbidden by sandbox policy",
                    target=executable,
                    metadata={"forbidden_binary": executable},
                )
            )

        # 5. Check allowed commands whitelist if specified
        if policy.allowed_commands is not None:
            if executable not in policy.allowed_commands:
                violations.append(
                    SecurityViolation(
                        category="UNAUTHORIZED_BINARY_EXECUTION",
                        severity=ViolationSeverity.CRITICAL,
                        message=f"Executable '{executable}' is not in allowed command whitelist",
                        target=executable,
                        metadata={"allowed_commands": policy.allowed_commands},
                    )
                )

        # 6. Sudo or privilege escalation flags
        if executable in ("sudo", "su", "doas") or "-u" in tokens and "root" in tokens:
            violations.append(
                SecurityViolation(
                    category="PRIVILEGE_ESCALATION",
                    severity=ViolationSeverity.CRITICAL,
                    message="Privilege escalation via superuser invocation is blocked",
                    target=cmd_str,
                )
            )

        # 7. Dangerous file modification flags on system root
        if executable in ("chmod", "chown") and any(
            t in ("-R", "-r", "--recursive") for t in tokens
        ) and any(t in ("/", "/*", "/etc", "/usr", "/System") for t in tokens):
            violations.append(
                SecurityViolation(
                    category="RECURSIVE_ROOT_PERMISSIONS_TAMPERING",
                    severity=ViolationSeverity.CRITICAL,
                    message="Recursive permission changes on root or system folders are forbidden",
                    target=cmd_str,
                )
            )

        is_allowed = len(violations) == 0
        return is_allowed, tokens, violations

    @classmethod
    def sanitize_environment(
        cls,
        env: Optional[Dict[str, str]],
        policy: SandboxPolicy,
    ) -> Dict[str, str]:
        """Strip sensitive credentials and API keys from child process environment."""
        source_env = os.environ.copy() if env is None else env.copy()

        if not policy.sanitize_environment:
            return source_env

        compiled_patterns = [re.compile(p) for p in policy.forbidden_env_patterns]
        sanitized: Dict[str, str] = {}

        for key, val in source_env.items():
            # Check if key matches any forbidden credential pattern
            is_forbidden = any(pat.search(key) for pat in compiled_patterns)
            if not is_forbidden:
                sanitized[key] = val

        return sanitized
