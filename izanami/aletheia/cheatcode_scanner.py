"""Cheatcode scanner — Layer 1 of Aletheia proof gate.

Region-aware static analysis of Foundry PoC files.
setUp() = world-staging (lenient), test*/invariant* = exploit body (strict).

Catches fabricated exploits that use vm.store/vm.deal/vm.etch to
fake vulnerable state rather than exploiting actual contract logic.
"""

import re
from dataclasses import dataclass, field
from enum import Enum


class ScanRegion(Enum):
    SETUP = "setUp"
    EXPLOIT = "exploit_body"
    GLOBAL = "global"


@dataclass
class ScanResult:
    rejected: list[str] = field(default_factory=list)
    review: list[str] = field(default_factory=list)
    region_violations: dict[str, list[str]] = field(default_factory=dict)


# Forbidden EVERYWHERE — these bypass contract logic entirely
_FORBIDDEN_GLOBAL = [
    re.compile(r"\bvm\.store\b"),
    re.compile(r"\bvm\.etch\b"),
    re.compile(r"\bvm\.mockCall\b"),
    re.compile(r"\bvm\.ffi\b"),
    re.compile(r"\bvm\.setNonce\b"),
    re.compile(r"\bvm\.broadcast\b"),
    # Raw precompile address (cheatcode backdoor)
    re.compile(r"0x7109709ECfa91a80626fF3989D68f67F5b1DD12D", re.I),
]

# Forbidden in EXPLOIT BODY only — allowed in setUp for test scaffolding
_FORBIDDEN_EXPLOIT = [
    re.compile(r"\bvm\.deal\b"),
    re.compile(r"\bhoax\s*\("),
    re.compile(r"\bstartHoax\s*\("),
    re.compile(r"\bdealEth\s*\("),
]

# Review (flag, don't reject) — may be legitimate
_REVIEW_PATTERNS = [
    re.compile(r"\bvm\.warp\b"),
    re.compile(r"\bvm\.roll\b"),
    re.compile(r"\bvm\.sign\b"),
    re.compile(r"\bvm\.prank\b"),
    re.compile(r"\bassembly\s*\{"),
]


def _classify_region(line: str, current_region: ScanRegion) -> ScanRegion:
    """Determine which region a line belongs to."""
    stripped = line.strip()
    if re.match(r"function\s+setUp\s*\(", stripped):
        return ScanRegion.SETUP
    if re.match(r"function\s+(test|invariant)\w*\s*\(", stripped):
        return ScanRegion.EXPLOIT
    return current_region


def scan(poc_source: str) -> ScanResult:
    """Scan a Foundry PoC for cheatcode violations.

    Returns ScanResult with rejected[] (hard stops) and review[] (flags).
    """
    result = ScanResult()
    region = ScanRegion.GLOBAL
    brace_depth = 0

    for lineno, line in enumerate(poc_source.splitlines(), 1):
        new_region = _classify_region(line, region)
        if new_region != region:
            region = new_region
            brace_depth = 0

        brace_depth += line.count("{") - line.count("}")

        # Check globally forbidden patterns
        for pat in _FORBIDDEN_GLOBAL:
            if pat.search(line):
                msg = f"L{lineno} [{region.value}]: {pat.pattern} — forbidden cheatcode"
                result.rejected.append(msg)
                result.region_violations.setdefault(region.value, []).append(msg)

        # Check exploit-body-only forbidden patterns
        if region == ScanRegion.EXPLOIT:
            for pat in _FORBIDDEN_EXPLOIT:
                if pat.search(line):
                    msg = f"L{lineno} [{region.value}]: {pat.pattern} — forbidden in exploit body"
                    result.rejected.append(msg)
                    result.region_violations.setdefault(region.value, []).append(msg)

        # Check review patterns (flag but don't reject)
        for pat in _REVIEW_PATTERNS:
            if pat.search(line):
                msg = f"L{lineno} [{region.value}]: {pat.pattern} — review recommended"
                result.review.append(msg)

    return result
