"""Izanami descent loop — iterative PoC generation with Aletheia gate feedback.

descend() drives the generate→certify→feedback loop:
  1. Build context from static analysis + RAG corpus + prior feedback
  2. Call LLM to generate PoC
  3. Run Aletheia certify() on generated PoC
  4. If CONFIRMED → return success
  5. If EXPLOIT_FAILED → feed revert reason back, retry
  6. If INVALID_PROOF → feed cheatcode violation back, retry
"""

import json
import logging
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from izanami.aletheia import certify, Verdict
from izanami.aletheia.certify import adversarial_precheck

log = logging.getLogger("izanami.descent")


@dataclass
class DescentResult:
    success: bool
    verdict: Verdict
    poc_source: str = ""
    attempt: int = 0
    total_attempts: int = 0
    review_flags: list[str] = field(default_factory=list)
    log_entries: list[dict] = field(default_factory=list)


@dataclass
class DescentConfig:
    max_attempts: int = 5
    llm_host: str = "http://127.0.0.1:8080"
    llm_model: str = "gemma4"
    fork_url: str = ""
    fork_block: Optional[int] = None
    project_path: str = ""
    log_path: str = "descent_log.jsonl"


_SYSTEM_PROMPT = """\
You are a smart contract security auditor generating Foundry test PoCs.

Rules:
1. The PoC MUST exploit actual contract logic — no vm.store, vm.etch, vm.deal in the test body
2. setUp() may use vm.deal to fund the attacker, but the test body must move value through contract calls
3. Include assertGt(attacker.balance, baseline) to prove value extraction
4. Import the target contract and interact through its public interface
5. Use fork mode — the contract is already deployed

If your previous attempt failed, the revert reason is provided. Fix the specific issue.
If your previous attempt was rejected for cheatcodes, remove the flagged patterns.
"""


def descend(
    surface_report: dict,
    config: DescentConfig,
    corpus_context: str = "",
) -> DescentResult:
    """Run the Izanami descent loop.

    Args:
        surface_report: Kuebiko/Shirohebi static analysis output
            (attack_surface, authority_graph, unguarded_movers)
        config: Descent loop configuration
        corpus_context: RAG-injected corpus examples

    Returns:
        DescentResult with final verdict and all attempt logs.
    """
    result = DescentResult(
        success=False,
        verdict=Verdict.EXPLOIT_FAILED,
        total_attempts=config.max_attempts,
    )

    feedback_history = []

    for attempt in range(1, config.max_attempts + 1):
        log.info("descent attempt %d/%d", attempt, config.max_attempts)
        result.attempt = attempt

        # 1. Build context
        context = _build_context(surface_report, corpus_context, feedback_history)

        # 2. Generate PoC via LLM
        poc_source = _call_llm(context, config)
        if not poc_source:
            log.error("LLM failed to generate PoC on attempt %d", attempt)
            feedback_history.append({
                "attempt": attempt,
                "error": "LLM generation failed",
            })
            continue

        result.poc_source = poc_source

        # 2b. Adversarial precheck (skip on attempt 1 — no baseline)
        if attempt > 1:
            should_proceed, precheck_reason = adversarial_precheck(
                poc_source, config.llm_host, config.llm_model,
            )
            if not should_proceed:
                log.info("precheck REJECTED attempt %d: %s", attempt, precheck_reason[:80])
                feedback_history.append({
                    "attempt": attempt,
                    "verdict": "PRECHECK_REJECTED",
                    "reason": precheck_reason,
                    "instruction": "The PoC was deemed unlikely to move value. Revise the exploit logic.",
                })
                continue

        # 3. Write PoC to project and certify
        poc_path = Path(config.project_path) / "test" / "Exploit.t.sol"
        poc_path.parent.mkdir(parents=True, exist_ok=True)
        poc_path.write_text(poc_source)

        cert = certify(
            poc_source=poc_source,
            project_path=config.project_path,
            fork_url=config.fork_url,
            fork_block=config.fork_block,
        )

        # 4. Log attempt
        entry = {
            "attempt": attempt,
            "verdict": cert.verdict.value,
            "rejected": cert.rejected,
            "review": cert.review,
            "revert_reason": cert.revert_reason,
            "timestamp": datetime.now().isoformat(),
        }
        result.log_entries.append(entry)
        _append_log(entry, config.log_path)

        # 5. Handle verdict
        if cert.verdict == Verdict.CONFIRMED:
            log.info("CONFIRMED on attempt %d", attempt)
            result.success = True
            result.verdict = Verdict.CONFIRMED
            return result

        if cert.verdict == Verdict.NEEDS_REVIEW:
            log.info("NEEDS_REVIEW on attempt %d — returning for manual review", attempt)
            result.success = True
            result.verdict = Verdict.NEEDS_REVIEW
            result.review_flags = cert.review
            return result

        if cert.verdict == Verdict.INVALID_PROOF:
            log.warning("INVALID_PROOF on attempt %d — %s", attempt, cert.rejected[:2])
            feedback_history.append({
                "attempt": attempt,
                "verdict": "INVALID_PROOF",
                "rejected": cert.rejected,
                "instruction": "Remove the flagged cheatcodes. The exploit must work through contract calls only.",
            })
            continue

        if cert.verdict == Verdict.EXPLOIT_FAILED:
            log.info("EXPLOIT_FAILED on attempt %d — %s", attempt, cert.revert_reason[:100])
            feedback_history.append({
                "attempt": attempt,
                "verdict": "EXPLOIT_FAILED",
                "revert_reason": cert.revert_reason,
                "test_output": cert.test_output[-500:] if cert.test_output else "",
                "instruction": "Fix the revert. The contract rejected the call — adjust parameters or call sequence.",
            })
            continue

    log.warning("descent exhausted %d attempts", config.max_attempts)
    return result


def _build_context(
    surface_report: dict,
    corpus_context: str,
    feedback_history: list[dict],
) -> str:
    """Build LLM prompt context from static analysis + RAG + feedback."""
    lines = ["## Target Analysis\n"]

    # Attack surface
    surface = surface_report.get("attack_surface", [])
    if surface:
        lines.append("### Attack Surface")
        for func in surface[:20]:
            lines.append(f"- {func}")
        lines.append("")

    # Unguarded movers (prime targets)
    movers = surface_report.get("unguarded_movers", [])
    if movers:
        lines.append("### Unguarded Value-Moving Functions (PRIORITY TARGETS)")
        for m in movers[:10]:
            lines.append(f"- {m}")
        lines.append("")

    # Authority graph
    auth = surface_report.get("authority_graph", {})
    if auth:
        lines.append("### Authority Graph")
        for func, guard in list(auth.items())[:15]:
            lines.append(f"- {func} → guarded by {guard}")
        lines.append("")

    # RAG corpus
    if corpus_context:
        lines.append(corpus_context)

    # Feedback from prior attempts
    if feedback_history:
        lines.append("## Prior Attempt Feedback\n")
        for fb in feedback_history[-3:]:  # last 3 attempts
            lines.append(f"### Attempt {fb['attempt']}: {fb.get('verdict', 'unknown')}")
            if fb.get("revert_reason"):
                lines.append(f"Revert: {fb['revert_reason'][:200]}")
            if fb.get("rejected"):
                lines.append(f"Rejected: {', '.join(fb['rejected'][:3])}")
            if fb.get("instruction"):
                lines.append(f"→ {fb['instruction']}")
            lines.append("")

    lines.append("Generate a complete Foundry test PoC (Exploit.t.sol) that exploits the target.")
    return "\n".join(lines)


def _call_llm(context: str, config: DescentConfig) -> str:
    """Call LLM to generate a PoC."""
    payload = {
        "model": config.llm_model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": context},
        ],
        "temperature": 0.7,
        "max_tokens": 4096,
    }

    url = f"{config.llm_host}/v1/chat/completions"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            response = json.loads(resp.read())
            content = response["choices"][0]["message"]["content"]
            return _extract_solidity(content)
    except Exception as e:
        log.error("LLM call failed: %s", e)
        return ""


def _extract_solidity(content: str) -> str:
    """Extract Solidity code from LLM response (may be in code blocks)."""
    # Try to extract from ```solidity ... ``` block
    import re
    match = re.search(r"```(?:solidity)?\s*\n(.*?)```", content, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no code block, check if the whole response looks like Solidity
    if "pragma solidity" in content or "function test" in content:
        return content.strip()
    return content.strip()


def _append_log(entry: dict, log_path: str):
    """Append descent log entry to JSONL file."""
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        log.warning("could not write descent log: %s", e)
