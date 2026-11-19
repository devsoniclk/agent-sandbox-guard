"""Unit tests for MCP server functions."""

import json
import pytest
from agent_sandbox_guard.mcp_server import create_mcp_server


def test_mcp_server_creation_or_skip():
    try:
        mcp = create_mcp_server()
        assert mcp is not None
    except ImportError:
        pytest.skip("fastmcp is not installed in current environment")
