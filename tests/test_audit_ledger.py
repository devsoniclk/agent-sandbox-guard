"""Unit tests for AuditLedger."""

import json
import pytest
from agent_sandbox_guard.audit_ledger import AuditLedger
from agent_sandbox_guard.types import SecurityViolation, ViolationSeverity


def test_genesis_hash():
    ledger = AuditLedger()
    assert ledger.latest_hash == "0" * 64
    assert ledger.compute_merkle_root() == "0" * 64
    assert ledger.verify_integrity() is True


def test_record_action_and_chaining():
    ledger = AuditLedger()
    v = SecurityViolation(
        category="ESCAPE_ATTEMPT",
        severity=ViolationSeverity.HIGH,
        message="Attempted to read /etc/passwd",
        target="/etc/passwd",
    )
    rec1 = ledger.record_action(
        agent_id="agent-1",
        tool_name="read_file",
        operation="READ",
        target="/etc/passwd",
        is_allowed=False,
        violations=[v],
    )
    assert rec1.previous_hash == "0" * 64
    assert rec1.record_hash != "0" * 64
    assert ledger.latest_hash == rec1.record_hash
    assert ledger.verify_integrity() is True

    rec2 = ledger.record_action(
        agent_id="agent-1",
        tool_name="write_file",
        operation="WRITE",
        target="/workspace/out.txt",
        is_allowed=True,
        violations=[],
    )
    assert rec2.previous_hash == rec1.record_hash
    assert ledger.latest_hash == rec2.record_hash
    assert ledger.verify_integrity() is True


def test_merkle_root_computation():
    ledger = AuditLedger()
    for i in range(5):
        ledger.record_action(
            agent_id="agent-1",
            tool_name="tool",
            operation="OP",
            target=f"target_{i}",
            is_allowed=True,
            violations=[],
        )
    merkle_root = ledger.compute_merkle_root()
    assert len(merkle_root) == 64
    assert merkle_root != "0" * 64


def test_tamper_detection():
    ledger = AuditLedger()
    ledger.record_action(
        agent_id="agent-1",
        tool_name="tool",
        operation="OP",
        target="target_1",
        is_allowed=True,
        violations=[],
    )
    ledger.record_action(
        agent_id="agent-1",
        tool_name="tool",
        operation="OP",
        target="target_2",
        is_allowed=True,
        violations=[],
    )
    assert ledger.verify_integrity() is True

    # Tamper with record 0
    ledger.records[0].target = "tampered_target"
    assert ledger.verify_integrity() is False


def test_to_jsonl():
    ledger = AuditLedger()
    ledger.record_action(
        agent_id="agent-1",
        tool_name="tool",
        operation="OP",
        target="target_1",
        is_allowed=True,
        violations=[],
    )
    jsonl = ledger.to_jsonl()
    lines = jsonl.strip().split("\n")
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["agent_id"] == "agent-1"
    assert parsed["target"] == "target_1"
