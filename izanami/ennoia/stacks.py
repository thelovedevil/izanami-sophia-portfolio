"""Stacks/Clarity ingestion — fetch Clarity contract sources from Hiro API.

Supports:
- Source fetching via Hiro /v2/contracts/source/{principal}/{name}
- Dependency extraction (contract-call?, use-trait, impl-trait)
- Recursive BFS over dependency graph to max_depth
"""

import json
import logging
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("izanami.ennoia.stacks")

_HIRO_API = "https://api.hiro.so"


@dataclass
class StacksManifest:
    principal: str
    contract_name: str
    contracts: dict[str, str] = field(default_factory=dict)  # name → source
    block_height: int = 0
    stx_balance: int = 0
    dependencies: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def fetch_source(principal: str, name: str, api_base: str = _HIRO_API) -> str:
    """Fetch verified Clarity source from Hiro API."""
    url = f"{api_base}/v2/contracts/source/{principal}/{name}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("source", "")
    except Exception as e:
        log.warning("failed to fetch %s.%s: %s", principal, name, e)
        return ""


def extract_dependencies(source: str) -> list[str]:
    """Extract contract dependencies from Clarity source.

    Patterns:
      (contract-call? .name ...)
      (use-trait ALIAS 'PRINCIPAL.name)
      (use-trait ALIAS .name)
      (impl-trait 'PRINCIPAL.name)
      (impl-trait .name)
    """
    import re
    deps = set()

    # contract-call? .name or 'PRINCIPAL.name
    for m in re.finditer(r"\(contract-call\?\s+(['\.][\w.-]+)", source):
        deps.add(m.group(1))

    # use-trait / impl-trait
    for m in re.finditer(r"\((?:use-trait|impl-trait)\s+\w+\s+(['\.][\w.-]+)", source):
        deps.add(m.group(1))

    return list(deps)


def ingest_stacks(
    principal: str,
    contract_name: str,
    api_base: str = _HIRO_API,
    max_depth: int = 3,
) -> StacksManifest:
    """Ingest a Stacks/Clarity contract with dependency resolution.

    BFS over the dependency graph up to max_depth.
    """
    manifest = StacksManifest(principal=principal, contract_name=contract_name)

    # Fetch root contract
    source = fetch_source(principal, contract_name, api_base)
    if not source:
        manifest.errors.append(f"root contract not found: {principal}.{contract_name}")
        return manifest

    manifest.contracts[contract_name] = source

    # BFS dependency resolution
    queue = extract_dependencies(source)
    visited = {contract_name}
    depth = 0

    while queue and depth < max_depth:
        next_queue = []
        for dep in queue:
            # Parse dependency reference
            if dep.startswith("'"):
                # Fully qualified: 'PRINCIPAL.name
                parts = dep.lstrip("'").rsplit(".", 1)
                dep_principal = parts[0] if len(parts) > 1 else principal
                dep_name = parts[-1]
            elif dep.startswith("."):
                # Local: .name
                dep_principal = principal
                dep_name = dep.lstrip(".")
            else:
                continue

            if dep_name in visited:
                continue
            visited.add(dep_name)

            dep_source = fetch_source(dep_principal, dep_name, api_base)
            if dep_source:
                manifest.contracts[dep_name] = dep_source
                manifest.dependencies.append(f"{dep_principal}.{dep_name}")
                next_queue.extend(extract_dependencies(dep_source))
            else:
                manifest.errors.append(f"dependency not found: {dep_principal}.{dep_name}")

        queue = next_queue
        depth += 1

    # Fetch block height and balance
    manifest.block_height = _fetch_block_height(api_base)
    manifest.stx_balance = _fetch_stx_balance(principal, api_base)

    log.info(
        "stacks ingest: %s.%s — %d contracts, %d deps, block %d",
        principal, contract_name, len(manifest.contracts),
        len(manifest.dependencies), manifest.block_height,
    )
    return manifest


def _fetch_block_height(api_base: str) -> int:
    try:
        url = f"{api_base}/v2/info"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("stacks_tip_height", 0)
    except Exception:
        return 0


def _fetch_stx_balance(principal: str, api_base: str) -> int:
    try:
        url = f"{api_base}/extended/v1/address/{principal}/stx"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
            return int(data.get("balance", 0))
    except Exception:
        return 0
