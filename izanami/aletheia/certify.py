"""Aletheia certifier — 3-layer proof gate for exploit PoCs.

Layer 1: Cheatcode scanner (static, regex)
Layer 2: Dynamic execution (forge test / vitest)
Layer 2b: Runtime trace backstop (cheatcode precompile in traces)
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .cheatcode_scanner import scan as cheatcode_scan

log = logging.getLogger("izanami.aletheia")


class Verdict(Enum):
    CONFIRMED = "CONFIRMED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    INVALID_PROOF = "INVALID_PROOF"
    EXPLOIT_FAILED = "EXPLOIT_FAILED"


@dataclass
class CertifyResult:
    verdict: Verdict
    rejected: list[str] = field(default_factory=list)
    review: list[str] = field(default_factory=list)
    test_output: str = ""
    revert_reason: str = ""
    traces: list[str] = field(default_factory=list)


# Cheatcode precompile addresses for Layer 2b trace backstop
_CHEATCODE_PRECOMPILES = {
    "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d",  # Vm
    "0x4e59b44847b379578588920ca78fbf26c0b4956c",  # CREATE2 deployer
}

_CHEAT_TRACE_PATTERNS = [
    "store", "etch", "deal", "mockCall", "ffi", "setNonce",
]

_FORGE_TIMEOUT = 600  # 10 minutes


def certify(
    poc_source: str,
    project_path: str | Path,
    fork_url: str = "",
    fork_block: int | None = None,
    ffi: bool = False,
) -> CertifyResult:
    """Run the 3-layer proof gate on a Foundry PoC.

    Args:
        poc_source: Solidity source of the test file
        project_path: Path to the Foundry project root
        fork_url: RPC URL for fork testing
        fork_block: Block number to pin fork
        ffi: Allow FFI (default False — security)

    Returns:
        CertifyResult with verdict, rejected/review lists, and test output.
    """
    result = CertifyResult(verdict=Verdict.CONFIRMED)

    # ── Layer 1: Cheatcode scanner (static) ──
    scan_result = cheatcode_scan(poc_source)
    result.rejected.extend(scan_result.rejected)
    result.review.extend(scan_result.review)

    if scan_result.rejected:
        log.warning("Layer 1 REJECT: %d violations", len(scan_result.rejected))
        result.verdict = Verdict.INVALID_PROOF
        return result

    # ── Layer 1b: Net-of-baseline assertion check ──
    if not _has_baseline_assertion(poc_source):
        result.review.append("No net-of-baseline assertion (assertGt(balance, baseline)) detected")

    # ── Layer 2: Dynamic execution (forge test) ──
    forge_result = _run_forge(project_path, fork_url, fork_block, ffi)
    result.test_output = forge_result.get("output", "")

    if forge_result.get("error"):
        log.error("forge execution error: %s", forge_result["error"])
        result.verdict = Verdict.EXPLOIT_FAILED
        result.revert_reason = forge_result.get("error", "")
        return result

    if not forge_result.get("success"):
        result.verdict = Verdict.EXPLOIT_FAILED
        result.revert_reason = _extract_revert_reason(forge_result.get("output", ""))
        log.info("Layer 2: test failed — %s", result.revert_reason[:100])
        return result

    # ── Layer 2b: Runtime trace backstop ──
    traces = forge_result.get("traces", [])
    trace_violations = _scan_traces(traces)
    if trace_violations:
        result.rejected.extend(trace_violations)
        result.verdict = Verdict.INVALID_PROOF
        log.warning("Layer 2b REJECT: cheatcode in traces — %s", trace_violations)
        return result

    # ── Verdict assembly ──
    if scan_result.review:
        result.verdict = Verdict.NEEDS_REVIEW
        log.info("NEEDS_REVIEW: %d review flags", len(scan_result.review))
    else:
        result.verdict = Verdict.CONFIRMED
        log.info("CONFIRMED: exploit validated")

    return result


def _run_forge(
    project_path: str | Path,
    fork_url: str,
    fork_block: int | None,
    ffi: bool,
) -> dict:
    """Execute forge test and return parsed results."""
    cmd = ["forge", "test", "--json", "-vvv"]

    if fork_url:
        cmd.extend(["--fork-url", fork_url])
    if fork_block is not None:
        cmd.extend(["--fork-block-number", str(fork_block)])

    env = None
    if not ffi:
        import os
        env = {**os.environ, "FOUNDRY_FFI": "false"}

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(project_path),
            capture_output=True,
            text=True,
            timeout=_FORGE_TIMEOUT,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"forge test timed out after {_FORGE_TIMEOUT}s", "success": False}
    except FileNotFoundError:
        return {"error": "forge not found — install Foundry", "success": False}

    output = proc.stdout + proc.stderr

    # Parse JSON output
    success = proc.returncode == 0
    traces = []

    # Try to extract JSON test results
    try:
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                data = json.loads(line)
                # Extract traces if present
                for suite in data.values():
                    if isinstance(suite, dict):
                        for test_result in suite.get("test_results", {}).values():
                            if isinstance(test_result, dict):
                                decoded = test_result.get("decoded_logs", [])
                                traces.extend(decoded)
                                raw_traces = test_result.get("traces", [])
                                if isinstance(raw_traces, list):
                                    traces.extend(str(t) for t in raw_traces)
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass

    return {
        "success": success,
        "output": output,
        "traces": traces,
        "returncode": proc.returncode,
    }


def _scan_traces(traces: list) -> list[str]:
    """Layer 2b: Scan runtime traces for cheatcode precompile calls."""
    violations = []
    for trace in traces:
        trace_str = str(trace).lower()
        for precompile in _CHEATCODE_PRECOMPILES:
            if precompile in trace_str:
                for cheat in _CHEAT_TRACE_PATTERNS:
                    if cheat in trace_str:
                        violations.append(
                            f"Trace backstop: {cheat} via precompile {precompile[:18]}..."
                        )
    return violations


def _extract_revert_reason(output: str) -> str:
    """Extract revert reason from forge output."""
    for line in output.splitlines():
        line = line.strip()
        if "revert" in line.lower() or "assertion" in line.lower():
            return line[:200]
    return "test failed (no revert reason extracted)"


def _has_baseline_assertion(poc_source: str) -> bool:
    """Check if PoC contains a net-of-baseline value assertion.

    Looks for pattern: assertGt(X.balance, baseline) or similar.
    This ensures vm.deal in setUp is neutralized — value must move
    through contract interaction, not cheatcode fabrication.
    """
    import re
    return bool(re.search(
        r"assertGt\s*\([^,]+\.balance\s*,\s*baseline",
        poc_source,
    ))


def adversarial_precheck(
    poc_source: str,
    llm_host: str = "http://127.0.0.1:8080",
    model: str = "gemma4",
) -> tuple[bool, str]:
    """Adversarial precheck — cheap LLM filter before expensive forge execution.

    Asks a small model: "will this PoC actually move value? why or why not?"
    Returns (should_proceed, reasoning).
    """
    prompt = (
        "Analyze this Foundry PoC. Will it actually extract value from the target contract "
        "through legitimate contract calls (not cheatcodes)? Answer YES or NO with one sentence.\n\n"
        f"```solidity\n{poc_source[:3000]}\n```"
    )

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 100,
    }

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{llm_host}/v1/chat/completions",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            response = json.loads(resp.read())
            content = response["choices"][0]["message"]["content"].strip()
            should_proceed = content.upper().startswith("YES")
            return should_proceed, content
    except Exception as e:
        log.warning("adversarial precheck failed: %s — proceeding", e)
        return True, "precheck unavailable"
