# Changelog

All notable changes to `agent-sandbox-guard` will be documented in this file.

## [0.1.0] - 2026-11-19

### Added
- PathJailer: Realpath canonicalization, symlink escape containment, and forbidden path veto.
- SubprocessInterceptor: AST command tokenization, reverse shell heuristic detection, catastrophic wipe defense, and environment variable scrubbing.
- OutputSanitizer: Neutralization of markdown/HTML image tracking beacons, indirect prompt injection defense, and output byte limits.
- NetworkEgressEnforcer: SSRF defense, cloud metadata blocklist, and private IP isolation.
- AuditLedger: Tamper-evident SHA-256 hash chaining with binary Merkle root verification.
- SandboxGuardEngine: Master orchestration facade with circuit breaker state machine.
- CLI: Command-line interface with `info`, `audit-path`, `audit-cmd`, `sanitize`, and `scan`.
- FastMCP Server: Model Context Protocol integration for AI agent runtimes.
- Comprehensive test suite with 55 unit tests and 82% code coverage.
