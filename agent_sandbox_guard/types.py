"""Core type definitions and schemas for agent-sandbox-guard."""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence


class ViolationSeverity(str, enum.Enum):
    """Severity classification for security boundary violations."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PathAccessMode(str, enum.Enum):
    """File system operation access mode."""

    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    DELETE = "DELETE"
    MKDIR = "MKDIR"


@dataclass(frozen=True)
class SecurityViolation:
    """Represents a detected security invariant violation or attempt."""

    category: str
    severity: ViolationSeverity
    message: str
    target: str
    timestamp: float = field(default_factory=time.time)
    mitigated: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert violation to a serializable dictionary."""
        return {
            "category": self.category,
            "severity": self.severity.value,
            "message": self.message,
            "target": self.target,
            "timestamp": self.timestamp,
            "mitigated": self.mitigated,
            "metadata": self.metadata,
        }


@dataclass
class SandboxPolicy:
    """Defines strict runtime containment rules and boundary policies."""

    allowed_read_roots: List[str] = field(default_factory=list)
    allowed_write_roots: List[str] = field(default_factory=list)
    forbidden_paths: List[str] = field(
        default_factory=lambda: [
            "/etc/shadow",
            "/etc/master.passwd",
            "/etc/sudoers",
            "~/.ssh",
            "~/.aws",
            "~/.gnupg",
            "~/.kube",
            "~/.config/gcloud",
            "~/.zshrc",
            "~/.bashrc",
            "~/.bash_profile",
            "~/.profile",
            "~/Library/Keychains",
            "/Library/Keychains",
            "~/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        ]
    )
    allow_subprocesses: bool = True
    allowed_commands: Optional[List[str]] = None
    forbidden_commands: List[str] = field(
        default_factory=lambda: [
            "sudo",
            "su",
            "doas",
            "nc",
            "netcat",
            "ncat",
            "socat",
            "chown",
            "chmod",
            "launchctl",
            "pfctl",
            "iptables",
            "nft",
            "systemctl",
            "service",
            "shutdown",
            "reboot",
            "init",
            "mkfs",
            "fdisk",
            "parted",
            "dd",
            "useradd",
            "usermod",
            "groupadd",
            "passwd",
        ]
    )
    allow_network: bool = False
    allowed_domains: List[str] = field(default_factory=list)
    sanitize_environment: bool = True
    forbidden_env_patterns: List[str] = field(
        default_factory=lambda: [
            r".*_KEY$",
            r".*_SECRET$",
            r".*_TOKEN$",
            r".*_PASSWORD$",
            r".*_PASSWD$",
            r"^AWS_.*",
            r"^GITHUB_.*",
            r"^OPENAI_.*",
            r"^ANTHROPIC_.*",
            r"^SSH_.*",
            r"^PRIVATE_.*",
            r"^SECRET_.*",
        ]
    )
    detect_indirect_injection: bool = True
    strip_markdown_beacons: bool = True
    max_output_bytes: int = 1_048_576  # 1MB limit per tool return
    enforce_circuit_breaker: bool = True
    max_critical_violations: int = 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to serializable dictionary."""
        return {
            "allowed_read_roots": self.allowed_read_roots,
            "allowed_write_roots": self.allowed_write_roots,
            "forbidden_paths": self.forbidden_paths,
            "allow_subprocesses": self.allow_subprocesses,
            "allowed_commands": self.allowed_commands,
            "forbidden_commands": self.forbidden_commands,
            "allow_network": self.allow_network,
            "allowed_domains": self.allowed_domains,
            "sanitize_environment": self.sanitize_environment,
            "forbidden_env_patterns": self.forbidden_env_patterns,
            "detect_indirect_injection": self.detect_indirect_injection,
            "strip_markdown_beacons": self.strip_markdown_beacons,
            "max_output_bytes": self.max_output_bytes,
            "enforce_circuit_breaker": self.enforce_circuit_breaker,
            "max_critical_violations": self.max_critical_violations,
        }


@dataclass
class AuditRecord:
    """Tamper-evident audit log record of a checked or executed action."""

    record_id: str
    timestamp: float
    agent_id: str
    tool_name: str
    operation: str
    target: str
    is_allowed: bool
    violations: List[SecurityViolation]
    record_hash: str
    previous_hash: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize audit record."""
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "target": self.target,
            "is_allowed": self.is_allowed,
            "violations": [v.to_dict() for v in self.violations],
            "record_hash": self.record_hash,
            "previous_hash": self.previous_hash,
            "metadata": self.metadata,
        }


@dataclass
class ToolCallVerdict:
    """Decision verdict for an intercepted agent tool call."""

    is_allowed: bool
    operation: str
    target: str
    violations: List[SecurityViolation] = field(default_factory=list)
    sanitized_args: Dict[str, Any] = field(default_factory=dict)
    audit_id: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize tool call verdict."""
        return {
            "is_allowed": self.is_allowed,
            "operation": self.operation,
            "target": self.target,
            "violations": [v.to_dict() for v in self.violations],
            "sanitized_args": self.sanitized_args,
            "audit_id": self.audit_id,
            "reason": self.reason,
        }


@dataclass
class SanitizedOutput:
    """Result of context/output sanitization."""

    is_safe: bool
    original_length: int
    cleaned_length: int
    cleaned_text: str
    beacons_removed: List[str] = field(default_factory=list)
    injection_alerts: List[str] = field(default_factory=list)
    violations: List[SecurityViolation] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize sanitized output."""
        return {
            "is_safe": self.is_safe,
            "original_length": self.original_length,
            "cleaned_length": self.cleaned_length,
            "cleaned_text": self.cleaned_text,
            "beacons_removed": self.beacons_removed,
            "injection_alerts": self.injection_alerts,
            "violations": [v.to_dict() for v in self.violations],
            "risk_score": self.risk_score,
        }
