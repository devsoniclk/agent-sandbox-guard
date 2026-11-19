"""agent-sandbox-guard: Runtime security containment, tool-call interception & kernel sandbox boundary for autonomous AI agents."""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Lakshitha Dananjaya"

from agent_sandbox_guard.audit_ledger import AuditLedger
from agent_sandbox_guard.engine import CircuitBreakerTrippedError, SandboxGuardEngine
from agent_sandbox_guard.network_egress import NetworkEgressEnforcer
from agent_sandbox_guard.output_sanitizer import OutputSanitizer
from agent_sandbox_guard.path_jailer import PathJailer
from agent_sandbox_guard.subprocess_interceptor import SubprocessInterceptor
from agent_sandbox_guard.types import (
    AuditRecord,
    PathAccessMode,
    SandboxPolicy,
    SanitizedOutput,
    SecurityViolation,
    ToolCallVerdict,
    ViolationSeverity,
)

__all__ = [
    "__version__",
    "SandboxGuardEngine",
    "CircuitBreakerTrippedError",
    "PathJailer",
    "SubprocessInterceptor",
    "OutputSanitizer",
    "NetworkEgressEnforcer",
    "AuditLedger",
    "SandboxPolicy",
    "SecurityViolation",
    "ViolationSeverity",
    "PathAccessMode",
    "AuditRecord",
    "ToolCallVerdict",
    "SanitizedOutput",
]
