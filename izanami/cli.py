"""Izanami-Sophia CLI — smart contract exploit validation."""

import argparse
import json
import logging
import sys

from izanami.ennoia.ingest import ingest
from izanami.aletheia import certify, Verdict
from izanami.descent.generator import descend, DescentConfig


def main():
    parser = argparse.ArgumentParser(description="Izanami-Sophia — smart contract exploit validation")
    sub = parser.add_subparsers(dest="command")

    # izanami ingest
    ingest_p = sub.add_parser("ingest", help="Ingest a contract (resolve proxy, fetch source, pin block)")
    ingest_p.add_argument("address", help="Contract address")
    ingest_p.add_argument("--rpc", required=True, help="RPC URL")
    ingest_p.add_argument("--chain", default="ethereum", help="Chain name")
    ingest_p.add_argument("--etherscan-key", default="", help="Etherscan API key")
    ingest_p.add_argument("-v", "--verbose", action="store_true")

    # izanami certify
    cert_p = sub.add_parser("certify", help="Run Aletheia proof gate on a PoC file")
    cert_p.add_argument("poc_file", help="Path to Foundry test .sol file")
    cert_p.add_argument("--project", required=True, help="Foundry project path")
    cert_p.add_argument("--fork-url", default="", help="RPC URL for fork")
    cert_p.add_argument("--fork-block", type=int, default=None, help="Block number to pin")
    cert_p.add_argument("-v", "--verbose", action="store_true")

    # izanami descend
    desc_p = sub.add_parser("descend", help="Run Izanami descent loop")
    desc_p.add_argument("--target", required=True, help="Contract address")
    desc_p.add_argument("--rpc", required=True, help="RPC URL")
    desc_p.add_argument("--chain", default="ethereum", help="Chain name")
    desc_p.add_argument("--project", required=True, help="Foundry project path")
    desc_p.add_argument("--attempts", type=int, default=5, help="Max descent attempts")
    desc_p.add_argument("--llm-host", default="http://127.0.0.1:8080", help="LLM server URL")
    desc_p.add_argument("--llm-model", default="gemma4", help="LLM model name")
    desc_p.add_argument("--etherscan-key", default="", help="Etherscan API key")
    desc_p.add_argument("-v", "--verbose", action="store_true")

    # izanami scan (cheatcode scanner only)
    scan_p = sub.add_parser("scan", help="Run cheatcode scanner on a PoC file")
    scan_p.add_argument("poc_file", help="Path to Foundry test .sol file")
    scan_p.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(
        level=level,
        format="[izanami:%(name)s] %(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "ingest":
        manifest = ingest(
            address=args.address,
            rpc_url=args.rpc,
            chain=args.chain,
            etherscan_key=args.etherscan_key,
        )
        print(json.dumps({
            "address": manifest.address,
            "chain": manifest.chain,
            "fork_block": manifest.fork_block,
            "proxy": {"kind": manifest.proxy.kind, "implementation": manifest.proxy.implementation},
            "sources": len(manifest.sources),
            "balance_eth": manifest.balance_wei / 1e18,
            "errors": manifest.errors,
        }, indent=2))

    elif args.command == "certify":
        poc_source = open(args.poc_file).read()
        result = certify(
            poc_source=poc_source,
            project_path=args.project,
            fork_url=args.fork_url,
            fork_block=args.fork_block,
        )
        print(f"Verdict: {result.verdict.value}")
        if result.rejected:
            print(f"Rejected: {len(result.rejected)}")
            for r in result.rejected:
                print(f"  {r}")
        if result.review:
            print(f"Review flags: {len(result.review)}")
            for r in result.review:
                print(f"  {r}")
        if result.revert_reason:
            print(f"Revert: {result.revert_reason}")
        sys.exit(0 if result.verdict in (Verdict.CONFIRMED, Verdict.NEEDS_REVIEW) else 1)

    elif args.command == "descend":
        # Ingest first
        manifest = ingest(
            address=args.target,
            rpc_url=args.rpc,
            chain=args.chain,
            etherscan_key=args.etherscan_key,
        )

        # Build surface report from Shirohebi if available
        surface_report = {
            "address": manifest.address,
            "proxy": manifest.proxy.kind,
            "code_addresses": manifest.code_addresses,
            "sources_available": len(manifest.sources),
        }

        # Try to get RAG context
        corpus_context = ""
        try:
            from kagami.retrieve import retrieve_for_web3
            corpus_context = retrieve_for_web3(
                context=f"smart contract {manifest.address} {manifest.chain}",
            )
        except ImportError:
            pass

        config = DescentConfig(
            max_attempts=args.attempts,
            llm_host=args.llm_host,
            llm_model=args.llm_model,
            fork_url=args.rpc,
            fork_block=manifest.fork_block,
            project_path=args.project,
        )

        result = descend(surface_report, config, corpus_context)

        print(f"\nDescent result: {result.verdict.value}")
        print(f"Attempts: {result.attempt}/{result.total_attempts}")
        if result.success:
            print("PoC saved to test/Exploit.t.sol")
        for entry in result.log_entries:
            print(f"  attempt {entry['attempt']}: {entry['verdict']}")

    elif args.command == "scan":
        from izanami.aletheia.cheatcode_scanner import scan
        poc_source = open(args.poc_file).read()
        result = scan(poc_source)

        if result.rejected:
            print(f"REJECTED — {len(result.rejected)} violations:")
            for r in result.rejected:
                print(f"  {r}")
        elif result.review:
            print(f"REVIEW — {len(result.review)} flags:")
            for r in result.review:
                print(f"  {r}")
        else:
            print("CLEAN — no cheatcode violations detected")

        sys.exit(1 if result.rejected else 0)


if __name__ == "__main__":
    main()
