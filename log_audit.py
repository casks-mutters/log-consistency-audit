#!/usr/bin/env python3
import os
import argparse
import sys
import time
import json
from typing import Any, Dict, List
from web3 import Web3

DEFAULT_RPC_A = os.getenv("RPC_A", "https://mainnet.infura.io/v3/your_api_key")
DEFAULT_RPC_B = os.getenv("RPC_B", "https://eth.llamarpc.com")

def connect(url: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        print(f"❌ Failed to connect: {url}")
        sys.exit(1)
    return w3

def keccak_json(obj: Any) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return "0x" + Web3.keccak(data).hex()

def canonical_log(log: Dict[str, Any]) -> Dict[str, Any]:
    """Strip non-deterministic keys and normalize types."""
    keep = {
        "address": log.get("address"),
        "blockNumber": int(log.get("blockNumber", 0)),
        "transactionHash": log.get("transactionHash"),
        "transactionIndex": int(log.get("transactionIndex", 0)),
        "logIndex": int(log.get("logIndex", 0)),
        "data": log.get("data"),
        "topics": list(log.get("topics", [])),
    }
    return keep

def fetch_logs(w3: Web3, from_block: int, to_block: int, address: str, topic0: str) -> List[Dict[str, Any]]:
    flt: Dict[str, Any] = {
        "fromBlock": from_block,
        "toBlock": to_block,
    }
    if address != "*":
        flt["address"] = Web3.to_checksum_address(address)
    if topic0 != "*":
        flt["topics"] = [topic0]

    try:
        logs = w3.eth.get_logs(flt)
    except Exception as e:
        print(f"⚠️ get_logs error on {w3.provider.endpoint_uri}: {e}")
        return []
    return [canonical_log(l) for l in logs]

def compare_logs(logs_a: List[Dict[str, Any]], logs_b: List[Dict[str, Any]]):
      # Normalize ordering to avoid RPC-specific ordering differences
    logs_a = sorted(logs_a, key=lambda l: (l["blockNumber"], l["transactionIndex"], l["logIndex"]))
    logs_b = sorted(logs_b, key=lambda l: (l["blockNumber"], l["transactionIndex"], l["logIndex"]))

    if logs_a == logs_b:
        return True, None


    root_a = keccak_json(logs_a)
    root_b = keccak_json(logs_b)

    len_a = len(logs_a)
    len_b = len(logs_b)

    # find first differing entry (if lengths are equal)
    first_diff = None
    if len_a == len_b:
        for i, (la, lb) in enumerate(zip(logs_a, logs_b)):
            if la != lb:
                first_diff = {"index": i, "a": la, "b": lb}
                break

    return False, {
        "lenA": len_a,
        "lenB": len_b,
        "rootA": root_a,
        "rootB": root_b,
        "firstDiff": first_diff,
    }

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Compare Ethereum logs between two RPC providers.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("from_block", type=int, help="Start block (inclusive)")
    p.add_argument("to_block", type=int, help="End block (inclusive)")
    p.add_argument("address", help="Contract address or '*' for any")
    p.add_argument("topic0", help="Topic0 (event signature) or '*' for any")
    p.add_argument("--rpcA", default=DEFAULT_RPC_A, help="RPC URL for provider A")
    p.add_argument("--rpcB", default=DEFAULT_RPC_B, help="RPC URL for provider B")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    from_block = args.from_block
    to_block = args.to_block
    address = args.address
    topic0 = args.topic0
    rpcA = args.rpcA
    rpcB = args.rpcB


    from_block = int(sys.argv[1])
    to_block = int(sys.argv[2])
    address = sys.argv[3]
    topic0 = sys.argv[4]
    rpcA = sys.argv[5] if len(sys.argv) > 5 else DEFAULT_RPC_A
    rpcB = sys.argv[6] if len(sys.argv) > 6 else DEFAULT_RPC_B

    if from_block < 0 or to_block < 0:
        print("❌ Blocks must be ≥ 0.")
        sys.exit(2)

    if from_block > to_block:
        from_block, to_block = to_block, from_block
        print("🔄 Swapped block range for ascending order.")

    if rpcA == rpcB:
        print("⚠️ rpcA and rpcB are identical — comparison may be meaningless.")

    if "your_api_key" in rpcA or "your_api_key" in rpcB:
        print("⚠️ One of the RPC URLs still uses an Infura placeholder — replace with a real key.")

    wA = connect(rpcA)
    wB = connect(rpcB)

    print(f"🌐 RPC A: {rpcA} (chainId={wA.eth.chain_id})")
    print(f"🌐 RPC B: {rpcB} (chainId={wB.eth.chain_id})")

    if wA.eth.chain_id != wB.eth.chain_id:
        print("⚠️ chainId mismatch between RPC A and B — logs are not comparable.")

    print(f"🔍 Fetching logs from blocks [{from_block}, {to_block}]…")
    t0 = time.monotonic()
    logs_a = fetch_logs(wA, from_block, to_block, address, topic0)
    logs_b = fetch_logs(wB, from_block, to_block, address, topic0)
    elapsed = time.monotonic() - t0

    print(f"📦 RPC A logs: {len(logs_a)}")
    print(f"📦 RPC B logs: {len(logs_b)}")

    ok, diff = compare_logs(logs_a, logs_b)

    if ok:
        root_logs = keccak_json(logs_a)
        print("✅ Logs match exactly across both providers.")
        print(f"🔏 Log set root: {root_logs}")
    else:
        print("❌ Log divergence detected!")
        print(json.dumps(diff, indent=2))

    print(f"⏱️ Elapsed: {elapsed:.2f}s")

if __name__ == "__main__":
    main()
