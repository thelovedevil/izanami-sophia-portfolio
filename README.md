# Izanami-Sophia - PROTOTYPE POC

LLM-driven smart contract exploit validation — gate-first, Immunefi-focused.

![Version](https://img.shields.io/badge/version-0.1.0--prototype-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Chains](https://img.shields.io/badge/chains-EVM%20%7C%20Stacks-orange)
![Stack](https://img.shields.io/badge/stack-Foundry%20%7C%20Clarinet%20%7C%20Slither-orange)

---

## What it is

Izanami-Sophia is a **gate-first smart contract exploit validation system**. An LLM generates exploit proof-of-concept code; a three-layer proof gate determines whether the exploit is real, fabricated, or failed. The gate was built and tested before the generator — if the gate cannot distinguish a real drain from a cheatcode-fabricated one, nothing downstream matters.

Targets Immunefi bug bounty programmes. Supports EVM (Solidity/Foundry) and Stacks (Clarity/Clarinet) chains. Currently a working prototype — the descent loop reaches the gate end-to-end, the gate correctly classifies all control cases, and the static analysers produce actionable surface maps. LLM output quality on local models is the active constraint.

---

## Architecture overview

```
                         ┌──────────────┐
                         │   Ennoia     │
                         │  Ingestion   │
                         │  proxy resolve│
                         │  fork-pin    │
                         │  source fetch │
                         └──────┬───────┘
                                │
                                ▼
                         ┌──────────────┐
                         │   Kuebiko    │
                         │  Static      │
                         │  Analysis    │
                         │  surface map │
                         │  detectors   │
                         └──────┬───────┘
                                │
                     ┌──────────┴──────────┐
                     │                     │
                     ▼                     ▼
              ┌─────────────┐      ┌─────────────┐
              │  Invariant  │      │   Izanami   │
              │  Fuzzing    │      │  Descent    │
              │  (optional) │      │  Loop       │
              │  forge/     │      │             │
              │  echidna/   │      │ LLM → PoC  │
              │  medusa     │      │     ↕       │
              └──────┬──────┘      │  feedback   │
                     │             │     ↕       │
                     │             │  attempt++  │
                     │             └──────┬──────┘
                     │                    │
                     │    ┌───────────────┘
                     │    │
                     ▼    ▼
              ┌──────────────┐
              │   Aletheia   │
              │  Proof Gate  │
              │              │
              │  Layer 1: Static cheatcode scan
              │  Layer 2: Dynamic execution (forge/clarinet)
              │  Layer 2b: Runtime trace backstop
              │  Layer 3: Net-of-baseline assertion
              │              │
              │  CONFIRMED │ INVALID_PROOF │ EXPLOIT_FAILED │ NEEDS_REVIEW
              └──────────────┘
```

---

## The Aletheia proof gate

The gate is the load-bearing component. Every design decision flows from: **the gate must never confirm a fabricated exploit**.

### Layer 1 — static cheatcode enforcement

Source-level scan of the PoC for forbidden Foundry cheatcodes.

**Forbidden anywhere** (state fabrication):
`vm.store`, `vm.etch`, `vm.mockCall`, `vm.ffi`, `vm.setNonce`, `vm.broadcast`, raw precompile address

**Forbidden in exploit body** (capital fabrication):
`vm.deal`, `hoax()`, `startHoax()`, `dealEth()` — allowed only in `setUp()` for victim TVL staging

**Allowed** (legitimate test infrastructure):
`vm.createSelectFork`, `vm.selectFork`, `vm.prank`, `vm.expectRevert`, `vm.expectEmit`, `vm.label`, `vm.snapshot`

**Require review** (privileged operations):
`vm.warp`, `vm.roll`, `vm.sign`, non-attacker impersonations, inline assembly

**Region model**: `setUp()` is world-staging (lenient). `test*`/`invariant*` functions are the exploit body (strict).

### Layer 2 — dynamic execution

The exploit must actually pass when executed against forked mainnet state.

- **EVM**: `forge test --fork-url --fork-block-number --json` with `FOUNDRY_FFI=false`
- **Stacks**: `npx vitest run` in an ephemeral Clarinet project with topologically-sorted contracts

A PoC that reverts or fails assertions returns `EXPLOIT_FAILED` — not a gate violation, just a failed hypothesis. Feedback (revert reason + decoded logs) feeds back to the LLM for the next attempt.

### Layer 2b — runtime trace backstop

Post-execution scan of the forge trace JSON for cheatcode precompile calls that survived Layer 1 (e.g., obfuscated via assembly). Catches: `store`, `etch`, `deal`, `mockCall`, `ffi`, `setNonce`.

### Layer 3 — net-of-baseline assertion

The structural backstop. Every PoC must record `attacker.balance` after `setUp()` completes and assert value gain at the end:

```solidity
uint256 baseline = attacker.balance;  // recorded AFTER setUp
// ... exploit ...
assertGt(attacker.balance, baseline, "no value moved");
```

This neutralises any `vm.deal` in `setUp()` — fabricated capital appears in the baseline and cancels out. Value must move through the exploit itself.

### Gate verdicts

| Verdict | Meaning | Action |
|---------|---------|--------|
| `CONFIRMED` | Fair, value-moving exploit | Register to finding bus |
| `INVALID_PROOF` | Layer 1 or 2b cheatcode violation | Reject — not a failed exploit, a fabricated one |
| `EXPLOIT_FAILED` | Fair PoC, but didn't move value | Feed revert reason back to LLM |
| `NEEDS_REVIEW` | Privileged prank without provenance, or Clarinet unavailable | Flag for human review |

### Control suite

The gate ships with four control tests that validate its own classification:

| Control | Expected verdict | What it tests |
|---------|-----------------|---------------|
| `PositiveControl.t.sol` | `CONFIRMED` | Real unguarded drain — the gate accepts genuine exploits |
| `NegativeControl.t.sol` | `INVALID_PROOF` | `vm.store` fabrication — the gate rejects fakes |
| `FailingControl.t.sol` | `EXPLOIT_FAILED` | Fair but reverts — the gate distinguishes failure from fraud |
| `ProvenancePositive.t.sol` | `CONFIRMED` or `NEEDS_REVIEW` | Privileged prank with/without provenance |

---

## Kuebiko — static analysis

Maps the attack surface before the LLM ever sees the contract. Produces structured output consumed by the descent loop as context, not conclusions.

### Solidity (via Slither)

| Output | Content |
|--------|---------|
| **attack_surface** | All public/external functions: visibility, payable, writes_state, sends_eth, modifiers, access_controlled |
| **authority_graph** | `Contract.function` → guard description (`modifier onlyOwner`, `require(msg.sender == admin)`) |
| **unguarded_movers** | Public functions that send ETH or write state with NO access control — prime exploit targets |
| **privileged_principals** | Extracted from modifiers + in-body sender checks — used by gate for provenance validation |
| **detectors** | Slither findings: reentrancy-eth, arbitrary-send-eth, controlled-delegatecall, suicidal, tx-origin, unchecked-transfer, incorrect-equality, etc. |

### Clarity (manual regex parsing)

| Detector | Pattern |
|----------|---------|
| **unguarded-transfer** | `stx-transfer?` / `ft-transfer?` without `asserts! (is-eq tx-sender ...)` |
| **unchecked-external-call** | `unwrap-panic` on `contract-call?` (should use `unwrap!` / `try!`) |
| **division-precision** | Integer division truncation risks in arithmetic |
| **principal-confusion** | `tx-sender` vs `contract-caller` mismatch in authorization checks |

Transfer direction analysis: `stx-transfer? ... tx-sender (as from)` = caller pays in (deposit, not exploitable). Transfer to `tx-sender` = potential drain.

---

## Ennoia — ingestion

Prepares the target for analysis. Resolves the actual code through proxy chains, pins fork state for reproducibility.

### EVM

1. **Proxy resolution**: EIP-1967 (transparent/UUPS), EIP-2535 (diamond), EIP-1167 (minimal proxy), OpenZeppelin legacy — follows up to 3 hops
2. **Fork-pin**: records block height at scan time via `cast block-number` — all forge tests execute against this snapshot
3. **Balance snapshot**: `cast balance` for context
4. **Verified source fetch**: Etherscan API → crytic-compile → Slither analysis

### Stacks

1. **Source fetch**: Hiro Stacks API for verified Clarity source
2. **Dependency extraction**: parse `contract-call?`, `use-trait`, `impl-trait` references
3. **Transitive resolution**: iteratively fetch missing dependencies until all references resolve
4. **Topological sort**: Kahn's algorithm orders contracts so dependencies compile before dependents

---

## The descent loop

The generator is deliberately simple — the gate does the hard work.

```
for attempt in 1..max_attempts:
    context = kuebiko_report + corpus_examples + feedback_from_prior_attempts
    poc = llm_writer(context)                    # LLM generates Solidity/TypeScript PoC

    if attempt > 1:
        precheck = adversarial_precheck(poc)      # Cheap Haiku pass: obvious logic flaws?
        if precheck.reject: continue

    verdict = aletheia.certify(poc)               # Three-layer gate

    match verdict:
        CONFIRMED    → return success
        NEEDS_REVIEW → return for human review
        INVALID_PROOF → feedback += "cheatcode violation"
        EXPLOIT_FAILED → feedback += revert_reason + decoded_logs
```

### Corpus-driven few-shot prompting

Real exploit templates (not prose instructions) indexed by vulnerability class:

| Solidity class | Trigger detectors |
|---------------|-------------------|
| reentrancy | `reentrancy-eth`, `reentrancy-no-eth` |
| access-control | `arbitrary-send-eth`, `suicidal` |
| delegatecall | `controlled-delegatecall` |
| tx-origin | `tx-origin` |
| first-deposit | `incorrect-equality` |

| Clarity class | Trigger detectors |
|--------------|-------------------|
| unguarded-transfer | `unguarded-transfer` |
| trait-impersonation | `unchecked-external-call` |
| arithmetic-precision | `division-precision` |
| principal-confusion | `principal-confusion` |

Matching examples are injected into the LLM context. The stable prefix (rules + corpus + target surface) is prompt-cached; only the feedback tail varies per attempt.

---

## Invariant fuzzing integration

Optional phase between Kuebiko and descent. Synthesises invariant tests from the authority graph:

1. `invariant_synth.synthesize()` generates Foundry invariant tests
2. `forge test --match-contract Invariant` runs fuzzing
3. Violations become high-priority hypotheses fed to the descent loop

Supported backends: Foundry (always available), Echidna (optional), Medusa (optional).

---

## Chain support

| Chain | Execution gate | Static analysis | Source fetch | Status |
|-------|---------------|----------------|-------------|--------|
| EVM (Ethereum, Polygon, Arbitrum, Optimism, Base) | Foundry (forge) | Slither | Etherscan API | Working |
| Stacks | Clarinet (vitest) | Clarity regex analyser | Hiro API | Working |

### Stacks-specific infrastructure

The Clarinet gate required solving several infrastructure problems:

- **vitest v4 incompatibility**: Clarinet SDK's `setupVM()` creates a bare VM context; vitest 4's forks pool changed internal VM handling. Pinned to vitest ^2.1.0.
- **Contract dependency ordering**: Clarity contracts must appear in `Clarinet.toml` after their dependencies. Solved with topological sort (Kahn's algorithm) on `.contract-name` references.
- **Transitive dependency resolution**: Deep dependencies (traits, data contracts) fetched iteratively from Hiro API until all references resolve.
- **Epoch configuration**: Clarity 2.1+ builtins (`is-in-mainnet`) require `epoch = "2.4"` on all contracts.
- **Trait reference patterns**: Both fully-qualified (`'PRINCIPAL.name`) and local (`.name`) trait references resolved via regex with group alternation.

---

## LLM backend hierarchy

| Priority | Backend | Use case |
|----------|---------|----------|
| 1 | Anthropic API | PoC writer (Sonnet) + adversarial precheck (Haiku), prompt caching |
| 2 | Claude CLI | Max subscription, flat cost — fallback when API key absent |
| 3 | llama.cpp / Ollama | Local inference — current quality constraint for Stacks targets |

VRAM budget management: `nvidia-smi` query → per-layer cost estimation → safe `n_gpu_layers` cap (max 12 for partial offload on complex architectures like Gemma 4 ISWA).

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| EVM execution | Foundry (forge test --fork, FFI disabled) |
| Stacks execution | Clarinet SDK + vitest (ephemeral project, topological sort) |
| Static analysis (Solidity) | Slither (crytic-compile, detector suite) |
| Static analysis (Clarity) | Custom regex analyser (4 detector classes) |
| Proxy resolution | cast storage reads (EIP-1967, EIP-2535, EIP-1167) |
| LLM inference | Anthropic API (Sonnet writer, Haiku precheck) → Claude CLI → llama.cpp |
| VRAM management | nvidia-smi budget + safe layer capping |
| Fuzzing | Foundry invariant, Echidna, Medusa |
| Checkpoint | DynamoDB + local JSONL (resumable across outages) |
| Corpus | JSONL few-shot templates indexed by vulnerability class |
| Testing | pytest — gate control suite, descent loop mock, Kuebiko fixtures |

---

## Design principles

**Gate-first** — the proof gate was built and tested with positive/negative/failing control cases before the generator existed. If the gate cannot distinguish real from fake, nothing else matters.

**No cheatcode exploits** — a PoC that fabricates state via `vm.store`, `vm.etch`, or `vm.deal` (outside setUp) is not a failed exploit, it is a fabricated one. The gate rejects fabrication at three independent layers.

**Feedback loop, not one-shot** — each failed attempt returns structured feedback (revert reason, decoded logs, cheatcode violations) to the LLM. The generator improves across attempts without human intervention.

**Deterministic testing** — the descent loop accepts a pluggable `poc_writer`, allowing mock-based testing of the full loop without LLM calls. The gate tests use Foundry control contracts with known verdicts.

**Cross-chain, same loop** — EVM and Stacks share the same descent loop logic. Only the gate path differs (forge vs clarinet). Adding a new chain means adding a new gate backend, not rewriting the loop.

**Graceful degradation** — Clarinet unavailable → `NEEDS_REVIEW` (not crash). Source fetch fails → manifest still usable for static analysis. API down → local JSONL checkpoint preserves progress.

---

## Status

Working prototype — private repository, available for review during hiring or engagement discussions.

The descent loop executes end-to-end on both EVM and Stacks targets. The gate correctly classifies all control cases. Static analysers produce actionable surface maps. The active constraint is LLM output quality on local models for Stacks/Clarity targets (TypeScript generation).
