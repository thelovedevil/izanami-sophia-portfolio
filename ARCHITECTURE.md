# Architecture — Izanami-Sophia v0.1.0

## System topology

```
                    ┌─────────────────────────────┐
                    │         run.py               │
                    │   CLI entry point             │
                    │   --target  --chain  --rpc    │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │         Ennoia               │
                    │   Ingestion + state pinning   │
                    │                               │
                    │   EVM:    proxy → impl → fork │
                    │   Stacks: principal → deps    │
                    │                               │
                    │   Output: TargetManifest       │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │         Kuebiko              │
                    │   Static analysis            │
                    │                               │
                    │   EVM:    Slither detectors    │
                    │   Stacks: regex analyser       │
                    │                               │
                    │   Output: KuebikoReport        │
                    │   (surface, authority, movers) │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │      Invariant fuzzing        │
                    │      (optional)               │
                    │                               │
                    │   invariant_synth → forge/    │
                    │   echidna/medusa              │
                    │                               │
                    │   violations → descent seeds   │
                    └──────────┬──────────────────┘
                               │
             ┌─────────────────▼──────────────────────┐
             │            Izanami descent loop          │
             │                                          │
             │   ┌─────────────────────────────────┐    │
             │   │  context = kuebiko + corpus +    │    │
             │   │           feedback               │    │
             │   │                                  │    │
             │   │  poc = llm_writer(context)       │    │
             │   │                                  │    │
             │   │  if attempt > 1:                 │    │
             │   │    precheck(poc)                  │    │
             │   │                                  │    │
             │   │  verdict = aletheia.certify(poc) │    │
             │   │                                  │    │
             │   │  CONFIRMED    → return ✓          │    │
             │   │  NEEDS_REVIEW → return ⚠          │    │
             │   │  INVALID_PROOF→ feedback(cheat)   │◄──┘
             │   │  EXPLOIT_FAILED→ feedback(revert) │───┘
             │   └─────────────────────────────────┘
             │                                          │
             └──────────────────────────────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │      descent_log.py           │
                    │   DynamoDB + local JSONL       │
                    │   Resumable across outages     │
                    └──────────────────────────────┘
```

---

## Ennoia — ingestion

### EVM path

```
ingest(address, rpc_url, chain, fork_block)
    │
    ├── proxy.resolve(address, rpc_url)
    │       Read EIP-1967 storage slots:
    │         0x360894...  (implementation)
    │         0xa3f0ad...  (beacon → implementation)
    │         0x7050c9...  (admin)
    │       Parse EIP-1167 minimal proxy bytecode
    │       Detect EIP-2535 diamond (facets via loupe)
    │       Follow up to max_hops=3
    │       Output: ProxyInfo(kind, implementation, beacon, facets)
    │
    ├── cast block-number --rpc-url
    │       Pin fork block for reproducibility
    │
    ├── cast balance address --rpc-url
    │       Snapshot for context
    │
    └── contract_fetcher(code_addresses)
            Etherscan API → verified source
            Output: Dict[address, source]
```

**Output**: `TargetManifest` — `address`, `chain`, `rpc_url`, `fork_block`, `proxy`, `code_addresses`, `constellation`, `balance_wei`, `sources`, `errors`.

### Stacks path

```
stacks_client.ingest(principal.contract-name, api_base, max_depth)
    │
    ├── fetch_source(principal, name)
    │       Hiro API: /v2/contracts/source/{principal}/{name}
    │       Returns verified Clarity source
    │
    ├── extract_dependencies(source)
    │       Parse: contract-call? .name
    │              use-trait ALIAS 'PRINCIPAL.name
    │              use-trait ALIAS .name
    │              impl-trait 'PRINCIPAL.name
    │              impl-trait .name
    │       Both fully-qualified and local .name forms
    │
    ├── Recursive fetch to max_depth
    │       BFS over dependency graph
    │       Each dep fetched from Hiro API
    │
    └── fetch_block_height(), fetch_stx_balance()
            Context for manifest
```

**Output**: `StacksManifest` — `principal`, `contracts` (Dict[name, source]), `block_height`, `stx_balance`, `errors`.

---

## Kuebiko — static analysis

### Solidity analyser (`static.py`)

```
analyze(target_path_or_address)
    │
    ├── Slither(target)
    │       crytic-compile for source resolution
    │       Run all built-in detectors
    │
    ├── Walk contracts_entry_points
    │       For each public/external function:
    │         - Read source from file_cache
    │         - Parse modifiers (onlyOwner, hasRole, etc.)
    │         - Parse in-body checks (require(msg.sender == ...))
    │         - Classify: access_controlled or attack_surface
    │         - Flag if: sends_eth, writes_state, payable
    │
    ├── Build authority_graph
    │       "Contract.function" → guard description
    │       Modifiers mapped: onlyOwner → owner, onlyAdmin → admin
    │       In-body: require(msg.sender == X) → X
    │
    ├── Extract unguarded_movers
    │       Filter: public + (sends_eth OR writes_state) + NOT access_controlled
    │       These are the prime exploit targets
    │
    └── Extract privileged_principals
            Set of principal names from modifiers + sender checks
            Used by Aletheia for provenance validation
```

**Output**: `KuebikoReport` — `attack_surface[]`, `authority_graph{}`, `unguarded_movers[]`, `privileged_principals{}`, `detectors[]`.

### Clarity analyser (`clarity_analyzer.py`)

```
analyze_manifest(contracts, principal)
    │
    ├── For each contract source:
    │     Parse define-public / define-read-only signatures
    │     Extract function surface (name, visibility, args)
    │
    ├── Authorization pattern detection
    │     asserts! (is-eq tx-sender ...)
    │     asserts! (is-eq contract-caller ...)
    │     contract-call? .dao check-is-protocol
    │     (var-get owner) comparisons
    │
    ├── Transfer direction analysis
    │     stx-transfer? FROM TO AMOUNT
    │     If FROM=tx-sender → deposit (caller pays in, not exploitable)
    │     If TO=tx-sender   → potential drain
    │     ft-transfer?, nft-transfer? same logic
    │
    └── Detector pass
          unguarded-transfer:     transfer without sender check
          unchecked-external-call: unwrap-panic on contract-call?
          division-precision:     integer division truncation
          principal-confusion:    tx-sender vs contract-caller mismatch
```

**Output**: `ClarityReport` — same schema as `KuebikoReport`, adapted for Clarity semantics.

---

## Aletheia — proof gate

### Layer architecture

```
certify(poc_source, project_path, ...)
    │
    ├── Layer 1: cheatcode_scanner.scan(poc_source)
    │       Region model:
    │         setUp()        → world-staging (lenient)
    │         test*/invariant* → exploit body (strict)
    │
    │       FORBIDDEN (anywhere):
    │         vm.store, vm.etch, vm.mockCall, vm.ffi,
    │         vm.setNonce, vm.broadcast, raw precompile addr
    │
    │       FORBIDDEN (exploit body only):
    │         vm.deal, hoax(), startHoax(), dealEth()
    │
    │       REVIEW (flag, don't reject):
    │         vm.warp, vm.roll, vm.sign,
    │         non-attacker prank, inline assembly
    │
    │       If reject[] non-empty → INVALID_PROOF (stop)
    │       If review[] non-empty → carry forward
    │
    ├── Layer 2: dynamic execution
    │       EVM:
    │         forge test --fork-url --fork-block-number --json
    │         FOUNDRY_FFI=false (belt-and-suspenders)
    │         Parse: success, test results, decoded logs, traces
    │         Timeout: 600s
    │       Stacks:
    │         create_ephemeral_project(contracts, poc, principal)
    │           - Write contracts + Clarinet.toml (toposorted)
    │           - npm install (cached node_modules)
    │           - epoch = "2.4" on all contracts
    │         npx vitest run
    │         Parse: pass/fail, error messages
    │
    │       If test fails → EXPLOIT_FAILED (not gate violation)
    │       Revert reason + logs → feedback for next attempt
    │
    ├── Layer 2b: runtime trace backstop
    │       Scan forge JSON trace for cheatcode precompile calls:
    │         store, etch, deal, mockCall, ffi, setNonce
    │       Catches obfuscation that Layer 1 regex misses
    │       If found → INVALID_PROOF
    │
    └── Verdict assembly
          reject[]  from L1/L2b  → INVALID_PROOF
          review[]  from L1      → NEEDS_REVIEW (if no other signal)
          test pass              → CONFIRMED
          test fail              → EXPLOIT_FAILED
```

### Clarity gate path

```
clarity_scanner.scan(poc_source)
    │
    ├── Forbidden patterns (TypeScript test body):
    │     simnet.mineBlock with fabricated sender
    │     Direct state manipulation outside contract calls
    │     Hardcoded principal impersonation without comment
    │
    ├── Review patterns:
    │     Block advancement (simnet.mineEmptyBlocks)
    │     Non-deployer callers
    │
    └── If clarinet unavailable → NEEDS_REVIEW (not crash)
```

### Net-of-baseline assertion (Layer 3)

The structural backstop that makes Layers 1 and 2b defence-in-depth rather than load-bearing:

```solidity
function test_exploit() public {
    uint256 baseline = attacker.balance;  // AFTER setUp
    // ... exploit body ...
    assertGt(attacker.balance, baseline, "no value moved");
}
```

Any `vm.deal` in `setUp()` is captured in `baseline` and neutralised. Value must move through the exploit contract interaction itself.

### Control suite

| Control file | Expected | Tests |
|-------------|----------|-------|
| `PositiveControl.t.sol` | CONFIRMED | Real unguarded `drain()` — gate accepts genuine exploits |
| `NegativeControl.t.sol` | INVALID_PROOF | `vm.store` writes fake balance — gate rejects fabrication |
| `FailingControl.t.sol` | EXPLOIT_FAILED | Fair PoC, target reverts — gate distinguishes failure from fraud |
| `ProvenancePositive.t.sol` | CONFIRMED/NEEDS_REVIEW | Privileged prank with/without authority_graph provenance |

---

## Izanami — descent loop

### Generator (`generator.py`)

```
descend(manifest, kuebiko_report, max_attempts, poc_writer)
    │
    ├── build_context(kuebiko_report)
    │       Compact surface map + authority graph
    │       Inject corpus examples matching detector classes
    │       Add TA guidance per vulnerability class
    │       Stable prefix (cacheable) + variable feedback tail
    │
    ├── For attempt in 1..max_attempts:
    │     │
    │     ├── poc = poc_writer(context + feedback)
    │     │       Priority: Anthropic Sonnet → Claude CLI → Ollama/llama.cpp
    │     │       Prompt caching: ~5min TTL on stable prefix
    │     │
    │     ├── adversarial_precheck(poc)  [attempt > 1]
    │     │       Haiku-class model: "will this PoC move value? why or why not?"
    │     │       Cheap filter before expensive forge execution
    │     │       Skipped on attempt 1 (no baseline for comparison)
    │     │
    │     ├── verdict = aletheia.certify(poc)
    │     │
    │     ├── descent_log.record_attempt(attempt, poc, verdict)
    │     │       DynamoDB + local JSONL (dual-write)
    │     │
    │     └── Match verdict:
    │           CONFIRMED     → return DescentResult(success)
    │           NEEDS_REVIEW  → return DescentResult(review)
    │           INVALID_PROOF → feedback += cheatcode violation details
    │           EXPLOIT_FAILED→ feedback += revert reason + decoded logs
    │
    └── Return DescentResult(exhausted) after max_attempts
```

### Feedback accumulation

Each failed attempt appends structured feedback:

```
attempt 1: EXPLOIT_FAILED
  revert: "err-not-authorized (u403)"
  → feedback: "The contract requires tx-sender == (var-get dao-address).
     Your PoC called deposit() directly. Route through the DAO contract."

attempt 2: INVALID_PROOF
  reject: ["vm.deal in test body"]
  → feedback: "vm.deal is forbidden outside setUp(). Stage victim
     TVL in setUp(), not in the test function."

attempt 3: EXPLOIT_FAILED
  revert: "insufficient-balance"
  → feedback: "The drain path requires staking first. Call stake()
     with the test account before attempting withdraw()."
```

The LLM sees all prior feedback in its context window. The stable prefix (target surface + rules + corpus) is prompt-cached; only the feedback tail grows per attempt.

### Pluggable `poc_writer`

`descend()` accepts any callable `(context, feedback, attempt) → str`. This allows:
- **Production**: Anthropic Sonnet with prompt caching
- **Fallback**: Claude CLI (Max subscription, flat cost)
- **Local**: Ollama/llama.cpp (no API cost, lower quality)
- **Testing**: Mock writer that returns predetermined PoC strings

The test suite uses a mock writer that fails on attempt 1 and succeeds on attempt 2, proving the feedback loop works end-to-end without LLM calls.

---

## Corpus — few-shot exploit templates

```
corpus/
├── solidity.jsonl     EVM exploit templates by vulnerability class
├── clarity.jsonl      Stacks exploit templates by vulnerability class
└── __init__.py        Retrieval: detector_checks → matching examples
```

### Retrieval logic

```
retrieve(detector_checks, chain, max_examples=3)
    │
    ├── Map detector names to corpus classes:
    │     reentrancy-eth       → reentrancy
    │     arbitrary-send-eth   → access-control
    │     controlled-delegatecall → delegatecall
    │     unguarded-transfer   → unguarded-transfer
    │     ...
    │
    ├── Load matching JSONL entries
    │     Each entry: {class, description, poc_template, notes}
    │
    └── Format as few-shot examples in LLM prompt
          "Here is a real PoC for a similar vulnerability class:"
```

Templates are real exploit patterns, not prose descriptions. The LLM sees concrete Solidity/TypeScript structure, reducing structural hallucination.

---

## Invariant fuzzing (`invariant_synth.py`)

```
synthesize(manifest, kuebiko_report)
    │
    ├── From authority_graph, generate invariant assertions:
    │     "owner should never change except via setOwner"
    │     "total supply should equal sum of all balances"
    │     "only privileged principals can call X"
    │
    ├── Write Foundry invariant test contract
    │     function invariant_owner_unchanged()
    │     function invariant_supply_consistent()
    │
    └── Return path to test contract
```

Violations discovered by fuzzing become high-priority seeds for the descent loop — they provide concrete counterexamples the LLM can turn into directed exploits.

---

## Ephemeral Clarinet project construction

The Stacks gate builds a temporary Clarinet project for each PoC attempt:

```
create_ephemeral_project(target_contracts, test_source, principal)
    │
    ├── Scope reduction
    │     Parse test_source for contract name references
    │     _reachable_contracts(): BFS from test refs
    │     Only include transitively-needed contracts
    │
    ├── Dependency resolution
    │     _resolve_missing_deps(contracts, principal)
    │     Iteratively fetch missing .contract-name refs from Hiro API
    │     Up to 5 rounds until all references satisfied
    │
    ├── Topological sort
    │     _toposort_contracts(): Kahn's algorithm
    │     Parse contract-call?, use-trait, impl-trait, contract-of refs
    │     Order in Clarinet.toml so deps compile before dependents
    │
    ├── Project scaffold
    │     Clarinet.toml (epoch = "2.4" on all contracts)
    │     vitest.config.ts (pool: "forks", singleFork: true)
    │     tsconfig.json (ESNext, bundler resolution)
    │     package.json (vitest ^2.1.0, clarinet-sdk ^3.9.0)
    │
    ├── npm install
    │     Cached node_modules (copy from /tmp/clarinet_node_cache)
    │     Timeout: 300s (first install with 18+ contracts is slow)
    │
    └── Return project path (caller rmtree's after gate)
```

### Key compatibility constraints

| Issue | Root cause | Fix |
|-------|-----------|-----|
| vitest v4 "Failed to start forks worker" | Clarinet SDK setupVM() incompatible with v4 forks pool | Pin vitest ^2.1.0 |
| "unresolved variable is-in-mainnet" | Clarity 2.1+ builtin unavailable on default simnet epoch | `epoch = "2.4"` on all contracts |
| "unresolved contract ststx-token" | Contracts not ordered by dependency in Clarinet.toml | Kahn's algorithm topological sort |
| Missing trait contracts | use-trait .name (local form) not parsed | Regex group alternation for both forms |
| npm timeout on 18+ contracts | 120s too short for first dependency resolution | 300s timeout + node_modules caching |

---

## Checkpoint and resume (`descent_log.py`)

Dual-write to DynamoDB and local JSONL:

```
record_attempt(descent_id, attempt, poc_source, verdict, feedback)
    │
    ├── DynamoDB (if available)
    │     Table: configurable via env
    │     Key: descent_id (hash) + attempt (range)
    │     TTL: 30 days
    │
    └── Local JSONL (always)
          aletheia/descent_log.jsonl
          One JSON object per line
          Fields: descent_id, attempt, timestamp, verdict, feedback_excerpt
```

Resume: on restart, `descent_log.load(descent_id)` returns all prior attempts. The descent loop skips completed attempts and resumes from `last_attempt + 1`.

---

## LLM backend routing

```
llm_router.py (shared with web2 pipeline)
    │
    ├── PoC writer (highest quality needed):
    │     1. Anthropic Sonnet (prompt-cached, ~10% input cost on hits)
    │     2. Claude CLI (Max subscription, flat cost)
    │     3. Ollama/llama.cpp (local, current quality bottleneck)
    │
    ├── Adversarial precheck (cheap classifier):
    │     1. Anthropic Haiku
    │     2. Local model
    │
    └── VRAM management (kagami/vram.py):
          nvidia-smi → free VRAM
          Model size / 40 ≈ MB per layer
          KV cache: ~0.25 MB per context token at Q4
          Partial offload capped at 12 layers
          (Gemma 4 ISWA triggers GGML_SCHED_MAX_SPLIT_INPUTS above 12)
```

---

## Key design decisions

**Gate before generator.**
The Aletheia gate was built, tested with control cases, and proven correct before any LLM-driven generator existed. This is deliberate — a generator that produces plausible-looking but fabricated exploits is worse than no generator at all. The gate is the load-bearing test; the generator is the hypothesis machine.

**Three independent rejection layers.**
Layer 1 (static), Layer 2b (trace), and Layer 3 (baseline assertion) each independently catch state fabrication. No single bypass defeats all three. This is defence-in-depth, not redundancy — each layer catches a different evasion class.

**`poc_writer` is pluggable.**
The descent loop's core logic (feedback accumulation, gate certification, checkpoint) is deterministic and testable without any LLM. Mock writers prove the loop's correctness; real writers are a configuration choice.

**Corpus over instructions.**
Real exploit templates (concrete code) reduce LLM structural hallucination compared to prose instructions ("write a reentrancy exploit"). The LLM imitates working patterns rather than generating from abstract descriptions.

**Prompt caching amortises cost.**
The stable prefix (target surface + rules + corpus examples) is identical across all attempts for a given target. Only the feedback tail varies. With ~5 minute TTL, a 5-attempt descent costs ~1× prefix + 5× tail, not 5× (prefix + tail).

**Graceful degradation everywhere.**
Every external dependency has a fallback: Clarinet unavailable → NEEDS_REVIEW. Source fetch fails → static analysis on available contracts. API down → local JSONL checkpoint. Forge missing → cannot run EVM gate (hard dependency, documented).
