"""Kuebiko static analysis — Slither-based surface mapping + authority graph.

Produces KuebikoReport:
  - attack_surface: public/external functions
  - authority_graph: function → guard mapping
  - unguarded_movers: functions that move value without access control
  - detectors: Slither detector findings
"""

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("izanami.kuebiko")


@dataclass
class FunctionSurface:
    contract: str
    name: str
    visibility: str  # public, external
    modifiers: list[str] = field(default_factory=list)
    sends_eth: bool = False
    writes_state: bool = False
    payable: bool = False
    access_controlled: bool = False
    guard: str = ""


@dataclass
class KuebikoReport:
    attack_surface: list[FunctionSurface] = field(default_factory=list)
    authority_graph: dict[str, str] = field(default_factory=dict)
    unguarded_movers: list[str] = field(default_factory=list)
    privileged_principals: set[str] = field(default_factory=set)
    detectors: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# Modifier patterns that indicate access control
_ACCESS_MODIFIERS = re.compile(
    r"onlyOwner|onlyAdmin|onlyRole|onlyMinter|onlyGovernance|"
    r"onlyOperator|onlyManager|whenNotPaused|nonReentrant|"
    r"onlyProxy|onlyDelegateCall|initializer|reinitializer",
    re.I,
)

# In-body require patterns for access control
_REQUIRE_SENDER = re.compile(
    r"require\s*\(\s*msg\.sender\s*==\s*(\w+)",
)

_REQUIRE_HAS_ROLE = re.compile(
    r"(?:require|_check)\s*\(\s*hasRole\s*\(\s*(\w+)",
)

# Value-moving patterns
_SENDS_ETH = re.compile(
    r"\.transfer\s*\(|\.send\s*\(|\.call\s*\{.*value|"
    r"payable\s*\(.*\)\.transfer|selfdestruct\s*\(",
)

_WRITES_STATE = re.compile(
    r"=\s*[^=]|\.push\s*\(|delete\s+\w+|"
    r"SSTORE|sstore\s*\(",
)


def analyze(
    source_path: str | Path,
    use_slither: bool = True,
) -> KuebikoReport:
    """Run Kuebiko static analysis on a Solidity project.

    Args:
        source_path: Path to Foundry project root or .sol file
        use_slither: Run Slither detectors (requires slither-analyzer installed)

    Returns:
        KuebikoReport with attack surface, authority graph, and unguarded movers.
    """
    report = KuebikoReport()
    source_path = Path(source_path)

    # Run Slither if available
    if use_slither:
        slither_results = _run_slither(source_path)
        report.detectors = slither_results.get("detectors", [])
        if slither_results.get("error"):
            report.errors.append(slither_results["error"])

    # Parse source files for surface mapping
    sol_files = []
    if source_path.is_file():
        sol_files = [source_path]
    else:
        sol_files = list(source_path.rglob("*.sol"))
        # Exclude test files and libraries
        sol_files = [
            f for f in sol_files
            if "/test/" not in str(f) and "/lib/" not in str(f) and "/node_modules/" not in str(f)
        ]

    for sol_file in sol_files:
        try:
            source = sol_file.read_text()
            _analyze_source(source, sol_file.stem, report)
        except Exception as e:
            report.errors.append(f"failed to analyze {sol_file.name}: {e}")

    # Build authority graph
    for func in report.attack_surface:
        key = f"{func.contract}.{func.name}"
        if func.access_controlled:
            report.authority_graph[key] = func.guard
        else:
            report.authority_graph[key] = "UNGUARDED"

    # Extract unguarded movers
    for func in report.attack_surface:
        if not func.access_controlled and (func.sends_eth or func.writes_state):
            report.unguarded_movers.append(f"{func.contract}.{func.name}")

    log.info(
        "kuebiko: %d surface functions, %d unguarded movers, %d detectors",
        len(report.attack_surface),
        len(report.unguarded_movers),
        len(report.detectors),
    )

    return report


def _analyze_source(source: str, contract_name: str, report: KuebikoReport):
    """Parse a Solidity source file for function surface and access patterns."""
    # Find function definitions
    func_pattern = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)\s+"
        r"((?:public|external)\b[^{]*)"
        r"\{",
        re.MULTILINE,
    )

    for match in func_pattern.finditer(source):
        name = match.group(1)
        signature_rest = match.group(2)

        # Extract body (rough — find matching brace)
        start = match.end()
        body = _extract_body(source, start)

        visibility = "public" if "public" in signature_rest else "external"
        payable = "payable" in signature_rest

        # Check modifiers
        modifiers = _ACCESS_MODIFIERS.findall(signature_rest)
        access_controlled = bool(modifiers)
        guard = ", ".join(modifiers) if modifiers else ""

        # Check in-body require(msg.sender == ...)
        sender_match = _REQUIRE_SENDER.search(body)
        if sender_match:
            principal = sender_match.group(1)
            access_controlled = True
            guard = guard + f", require(msg.sender == {principal})" if guard else f"require(msg.sender == {principal})"
            report.privileged_principals.add(principal)

        role_match = _REQUIRE_HAS_ROLE.search(body)
        if role_match:
            role = role_match.group(1)
            access_controlled = True
            guard = guard + f", hasRole({role})" if guard else f"hasRole({role})"

        # Check value movement
        sends_eth = bool(_SENDS_ETH.search(body)) or payable
        writes_state = bool(_WRITES_STATE.search(body))

        func_surface = FunctionSurface(
            contract=contract_name,
            name=name,
            visibility=visibility,
            modifiers=modifiers,
            sends_eth=sends_eth,
            writes_state=writes_state,
            payable=payable,
            access_controlled=access_controlled,
            guard=guard,
        )
        report.attack_surface.append(func_surface)


def _extract_body(source: str, start: int, max_chars: int = 5000) -> str:
    """Extract function body by matching braces."""
    depth = 1
    i = start
    end = min(start + max_chars, len(source))
    while i < end and depth > 0:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
        i += 1
    return source[start:i]


def _run_slither(project_path: Path) -> dict:
    """Run Slither and return parsed detector results."""
    try:
        proc = subprocess.run(
            ["slither", str(project_path), "--json", "-"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return {"error": "slither not found — install with pip install slither-analyzer"}
    except subprocess.TimeoutExpired:
        return {"error": "slither timed out after 120s"}

    detectors = []
    try:
        data = json.loads(proc.stdout)
        if isinstance(data, dict) and "results" in data:
            raw = data["results"].get("detectors", [])
            for d in raw:
                detectors.append({
                    "check": d.get("check", ""),
                    "impact": d.get("impact", ""),
                    "confidence": d.get("confidence", ""),
                    "description": d.get("description", "")[:300],
                })
    except json.JSONDecodeError:
        if proc.returncode != 0:
            return {"error": f"slither failed: {proc.stderr[:200]}", "detectors": []}

    return {"detectors": detectors}


def to_dict(report: KuebikoReport) -> dict:
    """Convert KuebikoReport to a dict suitable for descent loop context."""
    return {
        "attack_surface": [
            f"{f.contract}.{f.name}({f.visibility})"
            + (" [payable]" if f.payable else "")
            + (" [sends_eth]" if f.sends_eth else "")
            + (" [writes_state]" if f.writes_state else "")
            for f in report.attack_surface
        ],
        "authority_graph": report.authority_graph,
        "unguarded_movers": report.unguarded_movers,
        "privileged_principals": list(report.privileged_principals),
        "detector_count": len(report.detectors),
    }
