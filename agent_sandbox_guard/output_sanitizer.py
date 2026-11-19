"""Output and tool response sanitizer, markdown beacon stripper, and indirect prompt injection firewall."""

from __future__ import annotations

import re
from typing import List, Tuple

from agent_sandbox_guard.types import (
    SandboxPolicy,
    SanitizedOutput,
    SecurityViolation,
    ViolationSeverity,
)


class OutputSanitizer:
    """Sanitizes tool return payloads and model context to neutralize prompt injection and data exfiltration."""

    MARKDOWN_IMAGE_BEACON_REGEX = re.compile(
        r"!\[(.*?)\]\((https?://[^\s\)]+(?:\?[^\s\)]+)?)\)", re.IGNORECASE
    )
    HTML_IMG_BEACON_REGEX = re.compile(
        r"""<img\s+[^>]*?src=["'](https?://[^"']+)["'][^>]*?>""", re.IGNORECASE
    )

    INDIRECT_INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(?:all\s+)?prior\s+(?:system\s+)?instructions", re.IGNORECASE),
        re.compile(r"system\s*:\s*you\s+are\s+now", re.IGNORECASE),
        re.compile(r"new\s+(?:system\s+)?instruction\s*:", re.IGNORECASE),
        re.compile(r"(?:reveal|exfiltrate|print|dump)\s+(?:all\s+)?(?:secrets|tokens|api[_\s]keys|passwords)", re.IGNORECASE),
        re.compile(r"<system_override>.*?</system_override>", re.IGNORECASE | re.DOTALL),
        re.compile(r"AI\s*SAFETY\s*OVERRIDE\s*CODE", re.IGNORECASE),
        re.compile(r"base64\s*-d\s*\|.*sh", re.IGNORECASE),
        re.compile(r"curl\s+-[sS]?\s+https?://[^\s]+\s*\|\s*(?:bash|sh)", re.IGNORECASE),
    ]

    @classmethod
    def sanitize(
        cls,
        raw_text: str,
        policy: SandboxPolicy,
    ) -> SanitizedOutput:
        """Inspect and sanitize text output from external tools, web APIs, or model output."""
        if not raw_text:
            return SanitizedOutput(
                is_safe=True,
                original_length=0,
                cleaned_length=0,
                cleaned_text="",
            )

        original_len = len(raw_text)
        cleaned_text = raw_text
        beacons_removed: List[str] = []
        injection_alerts: List[str] = []
        violations: List[SecurityViolation] = []

        # 1. Byte limit check / truncation to prevent context buffer overflow
        if len(cleaned_text.encode("utf-8", errors="ignore")) > policy.max_output_bytes:
            violations.append(
                SecurityViolation(
                    category="OUTPUT_SIZE_EXCEEDED",
                    severity=ViolationSeverity.MEDIUM,
                    message=f"Output exceeded max limit of {policy.max_output_bytes} bytes and was truncated",
                    target="output_buffer",
                )
            )
            # Truncate at character boundary safely
            cleaned_text = cleaned_text[: policy.max_output_bytes // 2] + "\n[OUTPUT TRUNCATED BY AGENT-SANDBOX-GUARD]"

        # 2. Markdown and HTML image tracking beacon stripping
        if policy.strip_markdown_beacons:
            # Markdown beacons
            for match in cls.MARKDOWN_IMAGE_BEACON_REGEX.finditer(cleaned_text):
                url = match.group(2)
                beacons_removed.append(url)
                violations.append(
                    SecurityViolation(
                        category="TRACKING_BEACON_NEUTRALIZED",
                        severity=ViolationSeverity.HIGH,
                        message=f"Neutralized outbound image tracking beacon: {url}",
                        target=url,
                    )
                )

            # Replace markdown beacons with harmless placeholder
            cleaned_text = cls.MARKDOWN_IMAGE_BEACON_REGEX.sub(
                r"[BEACON NEUTRALIZED: \1]", cleaned_text
            )

            # HTML beacons
            for match in cls.HTML_IMG_BEACON_REGEX.finditer(cleaned_text):
                url = match.group(1)
                beacons_removed.append(url)
                violations.append(
                    SecurityViolation(
                        category="HTML_TRACKING_BEACON_NEUTRALIZED",
                        severity=ViolationSeverity.HIGH,
                        message=f"Neutralized HTML img tracking beacon: {url}",
                        target=url,
                    )
                )

            cleaned_text = cls.HTML_IMG_BEACON_REGEX.sub(
                r"[HTML IMAGE BEACON NEUTRALIZED]", cleaned_text
            )

        # 3. Indirect prompt injection heuristic detection
        if policy.detect_indirect_injection:
            for pattern in cls.INDIRECT_INJECTION_PATTERNS:
                matches = pattern.findall(cleaned_text)
                if matches:
                    alert = f"Detected injection signature: {pattern.pattern}"
                    injection_alerts.append(alert)
                    violations.append(
                        SecurityViolation(
                            category="INDIRECT_PROMPT_INJECTION_ATTEMPT",
                            severity=ViolationSeverity.HIGH,
                            message=f"Untrusted output contains adversarial prompt pattern: '{pattern.pattern}'",
                            target="tool_output_payload",
                            metadata={"pattern": pattern.pattern, "matches": str(matches[:3])},
                        )
                    )

        # Calculate risk score (0.0 = completely safe, 1.0 = critical risk)
        risk_score = 0.0
        if beacons_removed:
            risk_score += min(0.4, len(beacons_removed) * 0.2)
        if injection_alerts:
            risk_score += min(0.6, len(injection_alerts) * 0.3)
        risk_score = round(min(1.0, risk_score), 2)

        is_safe = risk_score < 0.5 and not any(
            v.severity == ViolationSeverity.CRITICAL for v in violations
        )

        return SanitizedOutput(
            is_safe=is_safe,
            original_length=original_len,
            cleaned_length=len(cleaned_text),
            cleaned_text=cleaned_text,
            beacons_removed=beacons_removed,
            injection_alerts=injection_alerts,
            violations=violations,
            risk_score=risk_score,
        )
