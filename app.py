#!/usr/bin/env python3
"""
consistency_audit_cli.py

Companion tool for the log-consistency-audit repo.

This script inspects logs for *per-request* or *per-session* consistency:
  - Reads one or more log files (JSON lines or plain text)
  - Groups log entries by a correlation ID (or any key)
  - Checks that state transitions follow an allowed order (e.g. NEW -> RUNNING -> DONE)
  - Emits a human-readable or JSON report of inconsistencies

Example usage:

  # Simple JSON lines logs:
  # {"ts": "2025-11-21T13:05:12Z", "request_id": "abc", "state": "NEW"}
  # {"ts": "2025-11-21T13:05:14Z", "request_id": "abc", "state": "RUNNING"}
  # {"ts": "2025-11-21T13:05:18Z", "request_id": "abc", "state": "DONE"}

  python consistency_audit_cli.py \
      --logs app.log \
      --format json \
      --id-field request_id \
      --state-field state \
      --timestamp-field ts \
      --allowed-order "NEW>RUNNING>DONE"

  # Plain-text logs, extracting fields via regex:
  # 2025-11-21T13:05:12Z [request_id=abc] state=NEW detail=...
  # 2025-11-21T13:05:14Z [request_id=abc] state=RUNNING detail=...
  # 2025-11-21T13:05:18Z [request_id=abc] state=DONE detail=...

  python consistency_audit_cli.py \
      --logs app.log \
      --format text \
      --regex-timestamp '(?P<ts>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)' \
      --regex-id 'request_id=(?P<id>[a-zA-Z0-9_-]+)' \
      --regex-state 'state=(?P<state>[A-Z_]+)' \
      --allowed-order "NEW>RUNNING>DONE" \
      --json

Exit codes:
  0 = audit passed, no inconsistencies found
  1 = configuration / argument error
  2 = failed to read / parse logs
  3 = inconsistencies found
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterable, Tuple


ISO8601_FMT = "%Y-%m-%dT%H:%M:%S%z"
ISO8601_Z_FMT = "%Y-%m-%dT%H:%M:%SZ"


@dataclasses.dataclass
class LogEvent:
    raw_line: str
    source_file: str
    line_no: int
    timestamp: Optional[datetime]
    id_value: str
    state: str


@dataclasses.dataclass
class Inconsistency:
    id_value: str
    type: str  # e.g. "out_of_order", "duplicate", "unknown_state", "regression"
    message: str
    events: List[LogEvent]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit logs for per-ID state transition consistency."
    )

    parser.add_argument(
        "--logs",
        nargs="+",
        required=True,
        help="One or more log files (or glob patterns) to inspect.",
    )

    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Log format: 'json' for JSON-lines, 'text' for plain text with regex extraction.",
    )

    # JSON fields
    parser.add_argument(
        "--id-field",
        default="id",
        help="JSON field name to use as correlation ID (default: id).",
    )
    parser.add_argument(
        "--state-field",
        default="state",
        help="JSON field name to use as state (default: state).",
    )
    parser.add_argument(
        "--timestamp-field",
        default="timestamp",
        help="JSON field name to use as timestamp (default: timestamp).",
    )

    # Text regex extraction
    parser.add_argument(
        "--regex-timestamp",
        help="Regex with named group 'ts' to extract timestamp from plain text logs.",
    )
    parser.add_argument(
        "--regex-id",
        help="Regex with named group 'id' to extract correlation ID from plain text logs.",
    )
    parser.add_argument(
        "--regex-state",
        help="Regex with named group 'state' to extract state from plain text logs.",
    )

    parser.add_argument(
        "--allowed-order",
        required=True,
        help=(
            "Allowed state order, e.g. 'NEW>RUNNING>DONE'. "
            "States not present here are treated as 'unknown_state'."
        ),
    )

    parser.add_argument(
        "--ignore-duplicates",
        action="store_true",
        help="Ignore duplicate consecutive states for the same ID.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON report instead of human-readable output.",
    )

    parser.add_argument(
        "--max-ids",
        type=int,
        default=None,
        help="Optionally limit the number of distinct IDs processed (for large logs).",
    )

    parser.add_argument(
        "--max-events-per-id",
        type=int,
        default=None,
        help="Optionally limit the number of events kept per ID (earliest events kept).",
    )

    parser.add_argument(
        "--timestamp-format",
        choices=("auto", "iso8601", "iso8601_z"),
        default="auto",
        help=(
            "How to parse timestamps when format=json or regex-timestamp is used. "
            "'auto' tries multiple variants. 'iso8601' uses %Y-%m-%dT%H:%M:%S%z, "
            "'iso8601_z' uses %Y-%m-%dT%H:%M:%SZ."
        ),
    )

    return parser.parse_args()


def expand_files(patterns: Iterable[str]) -> List[Path]:
    paths: List[Path] = []
    for pattern in patterns:
        # Support both literal paths and simple globs
        if any(ch in pattern for ch in "*?[]"):
            for p in Path(".").glob(pattern):
                if p.is_file():
                    paths.append(p)
        else:
            p = Path(pattern)
            if p.is_file():
                paths.append(p)
    # Deduplicate
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    return unique_paths


def parse_timestamp(raw: str, mode: str) -> Optional[datetime]:
    if raw is None:
        return None
    raw = raw.strip()
    if not raw:
        return None

    if mode == "iso8601":
        try:
            return datetime.strptime(raw, ISO8601_FMT)
        except ValueError:
            return None
    if mode == "iso8601_z":
        try:
            return datetime.strptime(raw, ISO8601_Z_FMT)
        except ValueError:
            return None

    # auto
    # try multiple common formats
    for fmt in (ISO8601_FMT, ISO8601_Z_FMT, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S%z"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def read_json_logs(
    paths: List[Path],
    id_field: str,
    state_field: str,
    ts_field: str,
    ts_mode: str,
    max_ids: Optional[int],
    max_events_per_id: Optional[int],
) -> Dict[str, List[LogEvent]]:
    events_by_id: Dict[str, List[LogEvent]] = defaultdict(list)
    stopped_ids = set()

    for path in paths:
        with path.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.rstrip("\n")

                if max_ids is not None and len(events_by_id) >= max_ids:
                    # Already reached max IDs; still allow events for already-seen IDs.
                    pass

                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    # Skip unparsable lines silently; could alternatively log.
                    continue

                id_value = obj.get(id_field)
                state = obj.get(state_field)
                ts_raw = obj.get(ts_field)

                if id_value is None or stat_
