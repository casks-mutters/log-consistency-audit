#!/usr/bin/env python3
import argparse
import os
import pathlib
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Quick wrapper around log_audit.py with env-based RPC defaults."
    )
    parser.add_argument(
        "--rpc-a",
        help="First RPC URL (defaults to $LOG_RPC_A).",
    )
    parser.add_argument(
        "--rpc-b",
        help="Second RPC URL (defaults to $LOG_RPC_B).",
    )
    parser.add_argument(
        "--from-block",
        type=int,
        required=True,
        help="Start block (inclusive).",
    )
    parser.add_argument(
        "--to-block",
        type=int,
        required=True,
        help="End block (inclusive).",
    )
    parser.add_argument(
        "--address",
        help="Optional contract address to filter logs.",
    )
    parser.add_argument(
        "--topic0",
        help="Optional topic0 to filter logs.",
    )
    parser.add_argument(
        "extra",
        nargs=argparse.REMAINDER,
        help="Any extra args to pass through to log_audit.py unchanged.",
    )

    args = parser.parse_args()

       source_a = "--rpc-a" if args.rpc_a else "LOG_RPC_A"
    source_b = "--rpc-b" if args.rpc_b else "LOG_RPC_B"
    print(f"Using RPC A from {source_a}", file=sys.stderr)
    print(f"Using RPC B from {source_b}", file=sys.stderr)


    if not rpc_a or not rpc_b:
        print(
            "ERROR: rpc-a / rpc-b not set. Provide --rpc-a/--rpc-b "
            "or set LOG_RPC_A / LOG_RPC_B in the environment.",
            file=sys.stderr,
        )
        sys.exit(1)

    repo_dir = pathlib.Path(__file__).resolve().parent
    log_audit_path = repo_dir / "log_audit.py"

    if not log_audit_path.is_file():
        print(f"ERROR: log_audit.py not found next to {__file__}", file=sys.stderr)
        sys.exit(1)

    cmd = [
        sys.executable,
        str(log_audit_path),
        "--rpc-a",
        rpc_a,
        "--rpc-b",
        rpc_b,
        "--from-block",
        str(args.from_block),
        "--to-block",
        str(args.to_block),
    ]

    if args.address:
        cmd += ["--address", args.address]
    if args.topic0:
        cmd += ["--topic0", args.topic0]

    # Forward any extra args (e.g. --json, --keccak-only, etc.)
    cmd += args.extra

    print(">> Running:", " ".join(cmd), file=sys.stderr)
    result = subprocess.run(cmd)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
