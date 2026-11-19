"""Model Context Protocol (MCP) server exposing sandbox guard tools to AI agents."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from agent_sandbox_guard.engine import SandboxGuardEngine
from agent_sandbox_guard.network_egress import NetworkEgressEnforcer
from agent_sandbox_guard.output_sanitizer import OutputSanitizer
from agent_sandbox_guard.path_jailer import PathJailer
from agent_sandbox_guard.subprocess_interceptor import SubprocessInterceptor
from agent_sandbox_guard.types import PathAccessMode, SandboxPolicy

# Global engine instance
_ENGINE = SandboxGuardEngine()


def create_mcp_server() -> Any:
    """Create and configure FastMCP server instance if installed."""
    try:
        from fastmcp import FastMCP  # type: ignore
    except ImportError:
        raise ImportError(
            "fastmcp is required to run the MCP server. Install with `pip install agent-sandbox-guard[mcp]`"
        )

    mcp = FastMCP("agent-sandbox-guard")

    @mcp.tool()
    def sandbox_inspect_tool_call(
        tool_name: str,
        arguments_json: str,
        agent_id: str = "ai-agent",
    ) -> str:
        """Inspect and validate an agent's intended tool call before execution against security policies."""
        try:
            args = json.loads(arguments_json) if isinstance(arguments_json, str) else arguments_json
        except Exception:
            args = {"raw": arguments_json}

        verdict = _ENGINE.intercept_tool_call(tool_name, args, agent_id)
        return json.dumps(verdict.to_dict(), indent=2)

    @mcp.tool()
    def sandbox_validate_path(
        path: str,
        mode: str = "read",
        allowed_roots_json: str = "[]",
    ) -> str:
        """Validate whether a file operation target is within allowed directory jail boundaries."""
        try:
            roots = json.loads(allowed_roots_json)
        except Exception:
            roots = []

        policy = SandboxPolicy()
        if roots:
            if mode.lower() == "read":
                policy.allowed_read_roots = roots
            else:
                policy.allowed_write_roots = roots

        access_mode = (
            PathAccessMode.READ
            if mode.lower() == "read"
            else (PathAccessMode.WRITE if mode.lower() == "write" else PathAccessMode.DELETE)
        )
        is_safe, canonical, violations = PathJailer.validate_access(path, access_mode, policy)
        return json.dumps(
            {
                "path": path,
                "canonical_path": canonical,
                "is_safe": is_safe,
                "violations": [v.to_dict() for v in violations],
            },
            indent=2,
        )

    @mcp.tool()
    def sandbox_audit_command(command: str) -> str:
        """Audit a shell command to detect dangerous binaries, reverse shells, or system commands."""
        is_safe, tokens, violations = SubprocessInterceptor.audit_command(command, _ENGINE.policy)
        return json.dumps(
            {
                "command": command,
                "tokens": tokens,
                "is_safe": is_safe,
                "violations": [v.to_dict() for v in violations],
            },
            indent=2,
        )

    @mcp.tool()
    def sandbox_sanitize_output(text: str) -> str:
        """Sanitize tool return content or web text to remove markdown tracking beacons and prompt injections."""
        sanitized = OutputSanitizer.sanitize(text, _ENGINE.policy)
        return json.dumps(sanitized.to_dict(), indent=2)

    @mcp.tool()
    def sandbox_get_audit_stats() -> str:
        """Retrieve audit statistics and cryptographic Merkle root of recorded actions."""
        summary = _ENGINE.get_audit_summary()
        return json.dumps(summary, indent=2)

    return mcp


def run_mcp_server() -> None:
    """Run MCP server over stdio transport."""
    server = create_mcp_server()
    server.run()
