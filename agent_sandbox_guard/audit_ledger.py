"""Cryptographic hash-chained audit ledger and Merkle verification tree for sandbox actions."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional

from agent_sandbox_guard.types import (
    AuditRecord,
    SecurityViolation,
    ViolationSeverity,
)


class AuditLedger:
    """Tamper-evident append-only ledger tracking all agent tool actions, checks, and violations."""

    GENESIS_HASH = "0" * 64

    def __init__(self) -> None:
        self.records: List[AuditRecord] = []
        self._latest_hash: str = self.GENESIS_HASH

    @property
    def latest_hash(self) -> str:
        """Return the cryptographic hash of the latest audit record."""
        return self._latest_hash

    def _compute_hash(
        self,
        previous_hash: str,
        record_id: str,
        timestamp: float,
        agent_id: str,
        tool_name: str,
        operation: str,
        target: str,
        is_allowed: bool,
        violations: List[SecurityViolation],
    ) -> str:
        """Compute deterministic SHA-256 hash for an audit record."""
        payload = {
            "previous_hash": previous_hash,
            "record_id": record_id,
            "timestamp": f"{timestamp:.6f}",
            "agent_id": agent_id,
            "tool_name": tool_name,
            "operation": operation,
            "target": target,
            "is_allowed": is_allowed,
            "violations": [v.to_dict() for v in violations],
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def record_action(
        self,
        agent_id: str,
        tool_name: str,
        operation: str,
        target: str,
        is_allowed: bool,
        violations: List[SecurityViolation],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Append an audited action to the ledger with hash chaining."""
        record_id = str(uuid.uuid4())
        timestamp = time.time()
        previous_hash = self._latest_hash

        record_hash = self._compute_hash(
            previous_hash=previous_hash,
            record_id=record_id,
            timestamp=timestamp,
            agent_id=agent_id,
            tool_name=tool_name,
            operation=operation,
            target=target,
            is_allowed=is_allowed,
            violations=violations,
        )

        record = AuditRecord(
            record_id=record_id,
            timestamp=timestamp,
            agent_id=agent_id,
            tool_name=tool_name,
            operation=operation,
            target=target,
            is_allowed=is_allowed,
            violations=violations,
            record_hash=record_hash,
            previous_hash=previous_hash,
            metadata=metadata or {},
        )

        self.records.append(record)
        self._latest_hash = record_hash
        return record

    def compute_merkle_root(self) -> str:
        """Compute the binary Merkle root over all recorded action hashes."""
        if not self.records:
            return self.GENESIS_HASH

        hashes = [r.record_hash for r in self.records]

        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])

            next_level: List[str] = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                next_level.append(hashlib.sha256(combined.encode("utf-8")).hexdigest())
            hashes = next_level

        return hashes[0]

    def verify_integrity(self) -> bool:
        """Verify the cryptographic hash chain of all records in the ledger."""
        if not self.records:
            return True

        expected_prev = self.GENESIS_HASH

        for record in self.records:
            if record.previous_hash != expected_prev:
                return False

            recalculated = self._compute_hash(
                previous_hash=record.previous_hash,
                record_id=record.record_id,
                timestamp=record.timestamp,
                agent_id=record.agent_id,
                tool_name=record.tool_name,
                operation=record.operation,
                target=record.target,
                is_allowed=record.is_allowed,
                violations=record.violations,
            )

            if recalculated != record.record_hash:
                return False

            expected_prev = record.record_hash

        return True

    def to_jsonl(self) -> str:
        """Serialize audit records as JSON Lines string."""
        return "\n".join(json.dumps(r.to_dict()) for r in self.records)
