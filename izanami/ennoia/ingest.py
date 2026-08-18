"""Ennoia ingestion — fetch contract source, resolve proxies, pin fork state.

Supports EVM (Etherscan + Sourcify) and produces a TargetManifest
for downstream Kuebiko analysis and Izanami descent.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("izanami.ennoia")

# EIP-1967 storage slots for proxy detection
_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"


@dataclass
class ProxyInfo:
    kind: str  # "eip1967", "eip1167", "eip2535", "none"
    implementation: str = ""
    beacon: str = ""
    admin: str = ""
    facets: list[str] = field(default_factory=list)


@dataclass
class TargetManifest:
    address: str
    chain: str
    rpc_url: str
    fork_block: int
    proxy: ProxyInfo
    code_addresses: list[str] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)  # address → source
    balance_wei: int = 0
    errors: list[str] = field(default_factory=list)


def _cast_call(args: list[str], rpc_url: str) -> str:
    """Run a cast command and return stdout."""
    cmd = ["cast"] + args + ["--rpc-url", rpc_url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout.strip() if result.returncode == 0 else ""
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _read_storage_slot(address: str, slot: str, rpc_url: str) -> str:
    """Read a storage slot via cast."""
    raw = _cast_call(["storage", address, slot], rpc_url)
    if raw and raw != "0x" + "0" * 64:
        # Extract address from 32-byte slot (last 20 bytes)
        return "0x" + raw[-40:]
    return ""


def resolve_proxy(address: str, rpc_url: str) -> ProxyInfo:
    """Detect and resolve proxy patterns."""
    impl = _read_storage_slot(address, _IMPL_SLOT, rpc_url)
    beacon = _read_storage_slot(address, _BEACON_SLOT, rpc_url)
    admin = _read_storage_slot(address, _ADMIN_SLOT, rpc_url)

    if impl:
        # Check if beacon points to impl
        if beacon:
            beacon_impl = _read_storage_slot(beacon, _IMPL_SLOT, rpc_url)
            if beacon_impl:
                impl = beacon_impl

        return ProxyInfo(
            kind="eip1967",
            implementation=impl,
            beacon=beacon,
            admin=admin,
        )

    # Check EIP-1167 minimal proxy (bytecode pattern)
    code = _cast_call(["code", address], rpc_url)
    if code and "363d3d373d3d3d363d73" in code.lower():
        # Extract implementation from bytecode
        idx = code.lower().index("363d3d373d3d3d363d73") + 20
        impl = "0x" + code[idx:idx + 40]
        return ProxyInfo(kind="eip1167", implementation=impl)

    return ProxyInfo(kind="none")


def ingest(
    address: str,
    rpc_url: str,
    chain: str = "ethereum",
    etherscan_key: str = "",
) -> TargetManifest:
    """Ingest a contract: resolve proxy, pin fork block, fetch source.

    Args:
        address: Contract address
        rpc_url: RPC endpoint
        chain: Chain name (ethereum, polygon, arbitrum, etc.)
        etherscan_key: Etherscan API key for source verification

    Returns:
        TargetManifest ready for Kuebiko/Izanami consumption.
    """
    log.info("ingesting %s on %s", address, chain)

    # Pin fork block
    block_str = _cast_call(["block-number"], rpc_url)
    fork_block = int(block_str) if block_str.isdigit() else 0

    # Resolve proxy
    proxy = resolve_proxy(address, rpc_url)
    code_addresses = [address]
    if proxy.implementation:
        code_addresses.append(proxy.implementation)
        log.info("proxy detected (%s) → impl %s", proxy.kind, proxy.implementation)

    # Get balance
    balance_str = _cast_call(["balance", address, "--ether"], rpc_url)
    balance_wei = 0
    try:
        balance_wei = int(float(balance_str) * 1e18) if balance_str else 0
    except ValueError:
        pass

    manifest = TargetManifest(
        address=address,
        chain=chain,
        rpc_url=rpc_url,
        fork_block=fork_block,
        proxy=proxy,
        code_addresses=code_addresses,
        balance_wei=balance_wei,
    )

    # Fetch verified source for each code address
    for addr in code_addresses:
        source = _fetch_source(addr, chain, etherscan_key)
        if source:
            manifest.sources[addr] = source
        else:
            manifest.errors.append(f"source not found for {addr}")

    log.info(
        "ingested: block=%d proxy=%s sources=%d balance=%.4f ETH",
        fork_block, proxy.kind, len(manifest.sources),
        balance_wei / 1e18,
    )

    return manifest


def _fetch_source(address: str, chain: str, api_key: str) -> str:
    """Fetch verified source from Etherscan or Sourcify."""
    # Try Sourcify first (no API key needed)
    source = _fetch_sourcify(address, chain)
    if source:
        return source

    # Fall back to Etherscan
    if api_key:
        return _fetch_etherscan(address, chain, api_key)

    return ""


def _fetch_sourcify(address: str, chain: str) -> str:
    """Fetch from Sourcify API."""
    chain_ids = {
        "ethereum": "1", "polygon": "137", "arbitrum": "42161",
        "optimism": "10", "base": "8453", "bsc": "56",
    }
    chain_id = chain_ids.get(chain, "1")
    url = f"https://sourcify.dev/server/files/{chain_id}/{address}"

    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            # Concatenate all .sol files
            sources = []
            if isinstance(data, list):
                for f in data:
                    if f.get("name", "").endswith(".sol"):
                        sources.append(f.get("content", ""))
            return "\n\n".join(sources) if sources else ""
    except Exception:
        return ""


def _fetch_etherscan(address: str, chain: str, api_key: str) -> str:
    """Fetch from Etherscan-compatible API."""
    base_urls = {
        "ethereum": "https://api.etherscan.io",
        "polygon": "https://api.polygonscan.com",
        "arbitrum": "https://api.arbiscan.io",
        "optimism": "https://api-optimistic.etherscan.io",
        "base": "https://api.basescan.org",
        "bsc": "https://api.bscscan.com",
    }
    base = base_urls.get(chain, "https://api.etherscan.io")
    url = f"{base}/api?module=contract&action=getsourcecode&address={address}&apikey={api_key}"

    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("status") == "1" and data.get("result"):
                return data["result"][0].get("SourceCode", "")
    except Exception:
        pass
    return ""
