#!/usr/bin/env python3
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
        "--show-ids",
        action="store_true",
        help="Print the list of IDs discovered and exit (no audit).",
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

                if id_value is None or state is None:
                    continue

                id_value = str(id_value)
                state = str(state)

                if max_ids is not None and id_value not in events_by_id and len(events_by_id) >= max_ids:
                    stopped_ids.add(id_value)
                    continue

                if max_events_per_id is not None and len(events_by_id[id_value]) >= max_events_per_id:
                    continue

                ts = parse_timestamp(str(ts_raw), ts_mode)

                events_by_id[id_value].append(
                    LogEvent(
                        raw_line=line,
                        source_file=str(path),
                        line_no=line_no,
                        timestamp=ts,
                        id_value=id_value,
                        state=state,
                    )
                )

    return events_by_id


def compile_optional(pattern: Optional[str]) -> Optional[re.Pattern]:
    if not pattern:
        return None
    return re.compile(pattern)


def read_text_logs(
    paths: List[Path],
    regex_ts: Optional[str],
    regex_id: str,
    regex_state: str,
    ts_mode: str,
    max_ids: Optional[int],
    max_events_per_id: Optional[int],
) -> Dict[str, List[LogEvent]]:
    re_ts = compile_optional(regex_ts)
    re_id = compile_optional(regex_id)
    re_state = compile_optional(regex_state)

    if re_id is None or re_state is None:
        print("ERROR: --regex-id and --regex-state are required for format=text", file=sys.stderr)
        sys.exit(1)

    events_by_id: Dict[str, List[LogEvent]] = defaultdict(list)

    for path in paths:
        with path.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.rstrip("\n")

                m_id = re_id.search(line)
                m_state = re_state.search(line)

                if not m_id or not m_state:
                    continue

                id_value = m_id.groupdict().get("id") or m_id.group(1)
                state = m_state.groupdict().get("state") or m_state.group(1)

                if id_value is None or state is None:
                    continue

                id_value = str(id_value)
                state = str(state)

                if max_ids is not None and id_value not in events_by_id and len(events_by_id) >= max_ids:
                    continue

                if max_events_per_id is not None and len(events_by_id[id_value]) >= max_events_per_id:
                    continue

                ts = None
                if re_ts is not None:
                    m_ts = re_ts.search(line)
                    if m_ts:
                        ts_raw = m_ts.groupdict().get("ts") or m_ts.group(0)
                        ts = parse_timestamp(str(ts_raw), ts_mode)

                events_by_id[id_value].append(
                    LogEvent(
                        raw_line=line,
                        source_file=str(path),
                        line_no=line_no,
                        timestamp=ts,
                        id_value=id_value,
                        state=state,
                    )
                )

    return events_by_id


def build_state_order(allowed_order: str) -> Tuple[Dict[str, int], List[str]]:
    """
    Parse a 'A>B>C' string into state -> order index map.
    """
    states = [s.strip() for s in allowed_order.split(">") if s.strip()]
    order_map = {state: idx for idx, state in enumerate(states)}
    return order_map, states


def audit_id_sequence(
    id_value: str,
    events: List[LogEvent],
    order_map: Dict[str, int],
    allowed_states: List[str],
    ignore_duplicates: bool,
) -> List[Inconsistency]:
    inconsistencies: List[Inconsistency] = []

    # Sort events by timestamp if available; otherwise keep original order
    events_sorted = sorted(
        events,
        key=lambda e: (e.timestamp or datetime.min, e.line_no),
    )

    last_order_idx: Optional[int] = None
    last_state: Optional[str] = None

    for ev in events_sorted:
        state = ev.state

        if state not in order_map:
            inconsistencies.append(
                Inconsistency(
                    id_value=id_value,
                    type="unknown_state",
                    message=f"Unknown state '{state}' for id={id_value}",
                    events=[ev],
                )
            )
            # unknown state: we don't update last_order_idx / last_state
            continue

        curr_idx = order_map[state]

        # Duplicate
        if last_state == state:
            if not ignore_duplicates:
                inconsistencies.append(
                    Inconsistency(
                        id_value=id_value,
                        type="duplicate_state",
                        message=f"Duplicate state '{state}' for id={id_value}",
                        events=[ev],
                    )
                )
        else:
            if last_order_idx is not None and curr_idx < last_order_idx:
                inconsistencies.append(
                    Inconsistency(
                        id_value=id_value,
                        type="regression",
                        message=(
                            f"State regression for id={id_value}: "
                            f"'{last_state}' -> '{state}'"
                        ),
                        events=[ev],
                    )
                )

            if last_order_idx is not None and curr_idx > last_order_idx + 1:
                missing_states = allowed_states[last_order_idx + 1 : curr_idx]
                inconsistencies.append(
                    Inconsistency(
                        id_value=id_value,
                        type="skipped_state",
                        message=(
                            f"Skipped states for id={id_value}: "
                            f"{' > '.join(missing_states)} (jumped to '{state}')"
                        ),
                        events=[ev],
                    )
                )

        last_order_idx = curr_idx
        last_state = state

    return inconsistencies


def audit_all_ids(
    events_by_id: Dict[str, List[LogEvent]],
    order_map: Dict[str, int],
    allowed_states: List[str],
    ignore_duplicates: bool,
) -> List[Inconsistency]:
    all_inconsistencies: List[Inconsistency] = []
    for id_value, events in events_by_id.items():
        incs = audit_id_sequence(
            id_value=id_value,
            events=events,
            order_map=order_map,
            allowed_states=allowed_states,
            ignore_duplicates=ignore_duplicates,
        )
        all_inconsistencies.extend(incs)
    return all_inconsistencies


def render_human(
    events_by_id: Dict[str, List[LogEvent]],
    inconsistencies: List[Inconsistency],
) -> None:
    total_ids = len(events_by_id)
    total_events = sum(len(v) for v in events_by_id.values())
    total_incs = len(inconsistencies)

    print(f"Total IDs: {total_ids}")
    print(f"Total events: {total_events}")
    print(f"Total inconsistencies: {total_incs}")
    print()

    if not inconsistencies:
        print("✅ No inconsistencies found.")
        return

    print("❌ Inconsistencies:")
    print("-" * 80)

    for i, inc in enumerate(inconsistencies, start=1):
        print(f"[{i}] ID={inc.id_value} TYPE={inc.type}")
        print(f"    {inc.message}")
        for ev in inc.events:
            ts_str = ev.timestamp.isoformat() if ev.timestamp else "NA"
            print(
                f"    at {ev.source_file}:{ev.line_no} "
                f"ts={ts_str} state={ev.state}"
            )
            print(f"      line: {ev.raw_line}")
        print("-" * 80)


def render_json(
    events_by_id: Dict[str, List[LogEvent]],
    inconsistencies: List[Inconsistency],
) -> None:
    def ev_to_dict(ev: LogEvent) -> Dict[str, Any]:
        return {
            "source_file": ev.source_file,
            "line_no": ev.line_no,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "id": ev.id_value,
            "state": ev.state,
            "raw_line": ev.raw_line,
        }

    payload = {
        "summary": {
            "total_ids": len(events_by_id),
            "total_events": sum(len(v) for v in events_by_id.values()),
            "total_inconsistencies": len(inconsistencies),
        },
        "inconsistencies": [
            {
                "id": inc.id_value,
                "type": inc.type,
                "message": inc.message,
                "events": [ev_to_dict(ev) for ev in inc.events],
            }
            for inc in inconsistencies
        ],
    }
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def main() -> None:
    args = parse_args()

    paths = expand_files(args.logs)
    if not paths:
        print("ERROR: no log files matched the provided patterns.", file=sys.stderr)
        sys.exit(1)

    order_map, ordered_states = build_state_order(args.allowed_order)
    if not order_map:
        print("ERROR: --allowed-order produced no valid states.", file=sys.stderr)
        sys.exit(1)

    # Read logs
    if args.format == "json":
        events_by_id = read_json_logs(
            paths=paths,
            id_field=args.id_field,
            state_field=args.state_field,
            ts_field=args.timestamp_field,
            ts_mode=args.timestamp_format,
            max_ids=args.max_ids,
            max_events_per_id=args.max_events_per_id,
        )
    else:
        events_by_id = read_text_logs(
            paths=paths,
            regex_ts=args.regex_timestamp,
            regex_id=args.regex_id,
            regex_state=args.regex_state,
            ts_mode=args.timestamp_format,
            max_ids=args.max_ids,
            max_events_per_id=args.max_events_per_id,
        )

    if not events_by_id:
        print("WARNING: No events were parsed from the provided logs.", file=sys.stderr)
    if args.show_ids:
        print("IDs discovered:")
        for idv in sorted(events_by_id.keys()):
            print(f"  {idv}")
        sys.exit(0)

    inconsistencies = audit_all_ids(
        events_by_id=events_by_id,
        order_map=order_map,
        allowed_states=ordered_states,
        ignore_duplicates=args.ignore_duplicates,
    )

    if args.json:
        render_json(events_by_id, inconsistencies)
    else:
        render_human(events_by_id, inconsistencies)

    if inconsistencies:
        sys.exit(3)
    sys.exit(0)


if __name__ == "__main__":
    main()
