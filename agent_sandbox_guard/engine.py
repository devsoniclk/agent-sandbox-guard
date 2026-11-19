"""Master SandboxGuardEngine orchestrating path jail, command interception, output sanitization, and audit ledger."""

from __future__ import annotations

import os
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from agent_sandbox_guard.audit_ledger import AuditLedger
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


class CircuitBreakerTrippedError(Exception):
    """Raised when the sandbox circuit breaker halts execution due to critical violations."""


class SandboxGuardEngine:
    """Master runtime security engine providing pre-execution interception and policy enforcement."""

    def __init__(self, policy: Optional[SandboxPolicy] = None) -> None:
        self.policy: SandboxPolicy = policy or SandboxPolicy()
        self.ledger: AuditLedger = AuditLedger()
        self.critical_violation_count: int = 0
        self.is_circuit_breaker_tripped: bool = False

    def reset_circuit_breaker(self) -> None:
        """Reset the circuit breaker and clear the critical violation counter."""
        self.critical_violation_count = 0
        self.is_circuit_breaker_tripped = False

    def _check_circuit_breaker(self) -> Optional[SecurityViolation]:
        """Verify circuit breaker status before evaluating action."""
        if self.is_circuit_breaker_tripped:
            return SecurityViolation(
                category="CIRCUIT_BREAKER_ACTIVE",
                severity=ViolationSeverity.CRITICAL,
                message="Sandbox circuit breaker is TRIPPED. All tool executions halted.",
                target="engine",
            )
        return None

    def _update_circuit_breaker(self, violations: List[SecurityViolation]) -> None:
        """Update circuit breaker state based on detected violations."""
        if not self.policy.enforce_circuit_breaker:
            return

        for v in violations:
            if v.severity == ViolationSeverity.CRITICAL:
                self.critical_violation_count += 1

        if self.critical_violation_count >= self.policy.max_critical_violations:
            self.is_circuit_breaker_tripped = True

    def intercept_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        agent_id: str = "agent-system",
    ) -> ToolCallVerdict:
        """Intercept, inspect, and approve/reject an agent's intended tool invocation."""
        cb_violation = self._check_circuit_breaker()
        if cb_violation:
            self.ledger.record_action(
                agent_id=agent_id,
                tool_name=tool_name,
                operation="TOOL_CALL_REJECTED",
                target=tool_name,
                is_allowed=False,
                violations=[cb_violation],
            )
            return ToolCallVerdict(
                is_allowed=False,
                operation="TOOL_CALL_REJECTED",
                target=tool_name,
                violations=[cb_violation],
                reason=cb_violation.message,
            )

        tool_lower = tool_name.lower()
        all_violations: List[SecurityViolation] = []
        target = "unknown"
        operation = "INSPECT"
        sanitized_args = arguments.copy()

        # 1. File Read Tools
        if any(keyword in tool_lower for keyword in ("read_file", "view_file", "cat", "open_file")):
            operation = "FILE_READ"
            target = str(arguments.get("path") or arguments.get("file_path") or arguments.get("file") or "")
            if target:
                is_safe, canonical, violations = PathJailer.is_safe_read(target, self.policy)
                all_violations.extend(violations)
                if canonical:
                    sanitized_args["canonical_path"] = canonical

        # 2. File Write / Create / Edit Tools
        elif any(keyword in tool_lower for keyword in ("write_file", "create_file", "edit_file", "save_file")):
            operation = "FILE_WRITE"
            target = str(arguments.get("path") or arguments.get("file_path") or arguments.get("file") or "")
            if target:
                is_safe, canonical, violations = PathJailer.is_safe_write(target, self.policy)
                all_violations.extend(violations)
                if canonical:
                    sanitized_args["canonical_path"] = canonical

        # 3. File Delete Tools
        elif any(keyword in tool_lower for keyword in ("delete_file", "remove_file", "unlink", "rm")):
            operation = "FILE_DELETE"
            target = str(arguments.get("path") or arguments.get("file_path") or arguments.get("file") or "")
            if target:
                is_safe, canonical, violations = PathJailer.is_safe_delete(target, self.policy)
                all_violations.extend(violations)
                if canonical:
                    sanitized_args["canonical_path"] = canonical

        # 4. Command / Subprocess Execution Tools
        elif any(keyword in tool_lower for keyword in ("bash", "exec", "shell", "run_command", "terminal", "cmd")):
            operation = "EXECUTE_COMMAND"
            command = arguments.get("command") or arguments.get("CommandLine") or arguments.get("cmd") or ""
            target = str(command)
            if command:
                is_safe, tokens, violations = SubprocessInterceptor.audit_command(command, self.policy)
                all_violations.extend(violations)
                sanitized_args["argv"] = tokens

        # 5. Network / HTTP Request Tools
        elif any(keyword in tool_lower for keyword in ("http", "curl", "fetch", "web_request", "get_url", "post_url")):
            operation = "NETWORK_REQUEST"
            url_target = str(arguments.get("url") or arguments.get("target") or arguments.get("endpoint") or "")
            target = url_target
            if url_target:
                is_safe, violations = NetworkEgressEnforcer.validate_destination(url_target, self.policy)
                all_violations.extend(violations)

        # Update circuit breaker
        self._update_circuit_breaker(all_violations)

        is_allowed = len(all_violations) == 0
        record = self.ledger.record_action(
            agent_id=agent_id,
            tool_name=tool_name,
            operation=operation,
            target=target,
            is_allowed=is_allowed,
            violations=all_violations,
            metadata={"arguments": str(arguments)},
        )

        reason = None
        if not is_allowed:
            reason = "; ".join(v.message for v in all_violations)

        return ToolCallVerdict(
            is_allowed=is_allowed,
            operation=operation,
            target=target,
            violations=all_violations,
            sanitized_args=sanitized_args,
            audit_id=record.record_id,
            reason=reason,
        )

    def safe_read_file(
        self,
        path: str,
        agent_id: str = "agent-system",
    ) -> Tuple[bool, Optional[str], List[SecurityViolation]]:
        """Perform a policy-guarded file read operation."""
        cb_violation = self._check_circuit_breaker()
        if cb_violation:
            return False, None, [cb_violation]

        is_safe, canonical, violations = PathJailer.is_safe_read(path, self.policy)
        self._update_circuit_breaker(violations)

        self.ledger.record_action(
            agent_id=agent_id,
            tool_name="safe_read_file",
            operation="READ",
            target=path,
            is_allowed=is_safe,
            violations=violations,
        )

        if not is_safe or not canonical:
            return False, None, violations

        try:
            with open(canonical, "r", encoding="utf-8") as f:
                content = f.read()
            return True, content, []
        except Exception as e:
            err_violation = SecurityViolation(
                category="FILE_IO_ERROR",
                severity=ViolationSeverity.LOW,
                message=f"I/O error during read: {str(e)}",
                target=canonical,
            )
            return False, None, [err_violation]

    def safe_write_file(
        self,
        path: str,
        content: str,
        agent_id: str = "agent-system",
    ) -> Tuple[bool, List[SecurityViolation]]:
        """Perform a policy-guarded file write operation."""
        cb_violation = self._check_circuit_breaker()
        if cb_violation:
            return False, [cb_violation]

        is_safe, canonical, violations = PathJailer.is_safe_write(path, self.policy)
        self._update_circuit_breaker(violations)

        self.ledger.record_action(
            agent_id=agent_id,
            tool_name="safe_write_file",
            operation="WRITE",
            target=path,
            is_allowed=is_safe,
            violations=violations,
        )

        if not is_safe or not canonical:
            return False, violations

        try:
            parent = os.path.dirname(canonical)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(canonical, "w", encoding="utf-8") as f:
                f.write(content)
            return True, []
        except Exception as e:
            err_violation = SecurityViolation(
                category="FILE_IO_ERROR",
                severity=ViolationSeverity.LOW,
                message=f"I/O error during write: {str(e)}",
                target=canonical,
            )
            return False, [err_violation]

    def safe_execute_command(
        self,
        command: Union[str, Sequence[str]],
        agent_id: str = "agent-system",
        env: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
    ) -> Tuple[bool, Optional[subprocess.CompletedProcess], List[SecurityViolation]]:
        """Perform a policy-guarded subprocess execution with sanitized environment."""
        cb_violation = self._check_circuit_breaker()
        if cb_violation:
            return False, None, [cb_violation]

        is_safe, tokens, violations = SubprocessInterceptor.audit_command(command, self.policy)
        self._update_circuit_breaker(violations)

        cmd_repr = command if isinstance(command, str) else " ".join(command)
        self.ledger.record_action(
            agent_id=agent_id,
            tool_name="safe_execute_command",
            operation="EXEC",
            target=cmd_repr,
            is_allowed=is_safe,
            violations=violations,
        )

        if not is_safe or not tokens:
            return False, None, violations

        sanitized_env = SubprocessInterceptor.sanitize_environment(env, self.policy)

        try:
            result = subprocess.run(
                tokens,
                capture_output=True,
                text=True,
                env=sanitized_env,
                timeout=timeout,
                check=False,
            )
            return True, result, []
        except Exception as e:
            err_violation = SecurityViolation(
                category="SUBPROCESS_EXEC_ERROR",
                severity=ViolationSeverity.MEDIUM,
                message=f"Failed to spawn subprocess: {str(e)}",
                target=cmd_repr,
            )
            return False, None, [err_violation]

    def sanitize_tool_result(
        self,
        result_text: str,
        agent_id: str = "agent-system",
    ) -> SanitizedOutput:
        """Sanitize raw tool output and record any detected injection attempts or tracking beacons."""
        output = OutputSanitizer.sanitize(result_text, self.policy)

        if output.violations:
            self._update_circuit_breaker(output.violations)
            self.ledger.record_action(
                agent_id=agent_id,
                tool_name="sanitize_tool_result",
                operation="SANITIZE_OUTPUT",
                target="tool_response",
                is_allowed=output.is_safe,
                violations=output.violations,
            )

        return output

    def get_audit_summary(self) -> Dict[str, Any]:
        """Return high-level audit and security statistics."""
        total_actions = len(self.ledger.records)
        allowed_count = sum(1 for r in self.ledger.records if r.is_allowed)
        blocked_count = total_actions - allowed_count
        all_violations = [v for r in self.ledger.records for v in r.violations]

        return {
            "total_actions_audited": total_actions,
            "actions_allowed": allowed_count,
            "actions_blocked": blocked_count,
            "total_violations": len(all_violations),
            "critical_violations": self.critical_violation_count,
            "circuit_breaker_tripped": self.is_circuit_breaker_tripped,
            "merkle_root": self.ledger.compute_merkle_root(),
            "ledger_integrity_verified": self.ledger.verify_integrity(),
        }
