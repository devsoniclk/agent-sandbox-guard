"""Command-line interface (CLI) for agent-sandbox-guard."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from agent_sandbox_guard import __version__
from agent_sandbox_guard.engine import SandboxGuardEngine
from agent_sandbox_guard.network_egress import NetworkEgressEnforcer
from agent_sandbox_guard.output_sanitizer import OutputSanitizer
from agent_sandbox_guard.path_jailer import PathJailer
from agent_sandbox_guard.subprocess_interceptor import SubprocessInterceptor
from agent_sandbox_guard.types import PathAccessMode, SandboxPolicy


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="agent-sandbox-guard",
        description="Runtime security containment, tool-call interception & kernel sandbox boundary for autonomous AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # info
    subparsers.add_parser("info", help="Display sandbox engine capabilities and policy defaults")

    # audit-path
    p_path = subparsers.add_parser("audit-path", help="Validate a filesystem path against sandbox boundaries")
    p_path.add_argument("path", help="Target path to evaluate")
    p_path.add_argument("--mode", choices=["read", "write", "delete"], default="read", help="Access mode (default: read)")
    p_path.add_argument("--root", action="append", default=[], help="Allowed root directories (repeatable)")
    p_path.add_argument("--json", action="store_true", help="Output results in JSON format")

    # audit-cmd
    p_cmd = subparsers.add_parser("audit-cmd", help="Audit a shell command for dangerous binaries and reverse shells")
    p_cmd.add_argument("command", help="Command string or executable")
    p_cmd.add_argument("--allow-subprocesses", action="store_true", default=True)
    p_cmd.add_argument("--json", action="store_true", help="Output results in JSON format")

    # sanitize
    p_san = subparsers.add_parser("sanitize", help="Sanitize text, neutralising tracking beacons and injection attacks")
    p_san.add_argument("text", nargs="?", default="", help="Text to sanitize (or reads from stdin if omitted)")
    p_san.add_argument("--json", action="store_true", help="Output results in JSON format")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan a directory or file for insecure agent tool implementations")
    p_scan.add_argument("target", help="Directory or file path to scan")
    p_scan.add_argument("--json", action="store_true", help="Output findings in JSON format")

    return parser


def handle_info(args: argparse.Namespace) -> int:
    """Print system info and sandbox capabilities."""
    sys.stdout.write(f"agent-sandbox-guard v{__version__}\n")
    sys.stdout.write("Platform: " + sys.platform + "\n")
    sys.stdout.write("Capabilities:\n")
    sys.stdout.write("  - Path Jailer (canonical realpath, symlink traversal containment)\n")
    sys.stdout.write("  - Subprocess Interceptor (tokenized AST, reverse shell blocking, dangerous binary veto)\n")
    sys.stdout.write("  - Output Sanitizer (Markdown/HTML beacon stripping, indirect prompt injection defense)\n")
    sys.stdout.write("  - Network Egress Firewall (SSRF defense, cloud metadata blocklist)\n")
    sys.stdout.write("  - Tamper-Evident SHA-256 Audit Ledger (Merkle root verification)\n")
    sys.stdout.write("  - FastMCP Protocol Server for AI Agent runtimes\n")
    return 0


def handle_audit_path(args: argparse.Namespace) -> int:
    """Evaluate path safety."""
    policy = SandboxPolicy()
    if args.root:
        if args.mode == "read":
            policy.allowed_read_roots = args.root
        else:
            policy.allowed_write_roots = args.root

    mode = PathAccessMode.READ if args.mode == "read" else (
        PathAccessMode.WRITE if args.mode == "write" else PathAccessMode.DELETE
    )

    is_safe, canonical, violations = PathJailer.validate_access(args.path, mode, policy)

    if args.json:
        result = {
            "path": args.path,
            "canonical_path": canonical,
            "mode": mode.value,
            "is_safe": is_safe,
            "violations": [v.to_dict() for v in violations],
        }
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
    else:
        status = "PASSED (SAFE)" if is_safe else "BLOCKED (VIOLATION)"
        sys.stdout.write(f"Target:    {args.path}\n")
        sys.stdout.write(f"Canonical: {canonical}\n")
        sys.stdout.write(f"Status:    {status}\n")
        if violations:
            sys.stdout.write("Violations:\n")
            for v in violations:
                sys.stdout.write(f"  [{v.severity.value}] {v.category}: {v.message}\n")

    return 0 if is_safe else 1


def handle_audit_cmd(args: argparse.Namespace) -> int:
    """Evaluate command safety."""
    policy = SandboxPolicy(allow_subprocesses=args.allow_subprocesses)
    is_safe, tokens, violations = SubprocessInterceptor.audit_command(args.command, policy)

    if args.json:
        result = {
            "command": args.command,
            "tokens": tokens,
            "is_safe": is_safe,
            "violations": [v.to_dict() for v in violations],
        }
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
    else:
        status = "PASSED (SAFE)" if is_safe else "BLOCKED (VIOLATION)"
        sys.stdout.write(f"Command: {args.command}\n")
        sys.stdout.write(f"Tokens:  {tokens}\n")
        sys.stdout.write(f"Status:  {status}\n")
        if violations:
            sys.stdout.write("Violations:\n")
            for v in violations:
                sys.stdout.write(f"  [{v.severity.value}] {v.category}: {v.message}\n")

    return 0 if is_safe else 1


def handle_sanitize(args: argparse.Namespace) -> int:
    """Sanitize text."""
    text = args.text
    if not text and not sys.stdin.isatty():
        text = sys.stdin.read()

    policy = SandboxPolicy()
    output = OutputSanitizer.sanitize(text, policy)

    if args.json:
        sys.stdout.write(json.dumps(output.to_dict(), indent=2) + "\n")
    else:
        sys.stdout.write(f"Safe:          {output.is_safe}\n")
        sys.stdout.write(f"Risk Score:    {output.risk_score}\n")
        sys.stdout.write(f"Beacons Found: {len(output.beacons_removed)}\n")
        sys.stdout.write(f"Injections:    {len(output.injection_alerts)}\n")
        sys.stdout.write("Cleaned Text:\n" + output.cleaned_text + "\n")

    return 0 if output.is_safe else 1


def handle_scan(args: argparse.Namespace) -> int:
    """Scan directory or files for security issues in agent implementations."""
    target = os.path.realpath(args.target)
    findings = []

    dangerous_patterns = [
        ("shell=True", "CRITICAL", "subprocess call using shell=True allows arbitrary command injection"),
        ("os.system(", "CRITICAL", "os.system executes raw unescaped shell strings"),
        ("OPENAI_API_KEY", "HIGH", "Hardcoded or exposed OpenAI API key reference"),
        ("ANTHROPIC_API_KEY", "HIGH", "Hardcoded or exposed Anthropic API key reference"),
        ("AWS_SECRET_ACCESS_KEY", "CRITICAL", "Hardcoded AWS secret key reference"),
        ("/etc/shadow", "CRITICAL", "Reference to system shadow password file"),
    ]

    files_to_scan = []
    if os.path.isfile(target):
        files_to_scan.append(target)
    elif os.path.isdir(target):
        for root, _, files in os.walk(target):
            if any(part in root for part in (".git", "__pycache__", "venv", ".pytest_cache")):
                continue
            for file in files:
                if file.endswith((".py", ".sh", ".js", ".ts", ".json", ".yaml", ".yml")):
                    files_to_scan.append(os.path.join(root, file))

    for filepath in files_to_scan:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            for pattern, severity, msg in dangerous_patterns:
                if pattern in content:
                    findings.append({
                        "file": filepath,
                        "pattern": pattern,
                        "severity": severity,
                        "message": msg,
                    })
        except Exception:
            continue

    if args.json:
        sys.stdout.write(json.dumps({"target": target, "findings": findings}, indent=2) + "\n")
    else:
        sys.stdout.write(f"Scanned {len(files_to_scan)} files in {target}\n")
        if not findings:
            sys.stdout.write("No security vulnerabilities identified. Clean scan!\n")
        else:
            sys.stdout.write(f"Found {len(findings)} potential security issues:\n")
            for f in findings:
                sys.stdout.write(f"  [{f['severity']}] {f['file']}: {f['message']}\n")

    return 0 if not findings else 1


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.subcommand or args.subcommand == "info":
        return handle_info(args)
    elif args.subcommand == "audit-path":
        return handle_audit_path(args)
    elif args.subcommand == "audit-cmd":
        return handle_audit_cmd(args)
    elif args.subcommand == "sanitize":
        return handle_sanitize(args)
    elif args.subcommand == "scan":
        return handle_scan(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
