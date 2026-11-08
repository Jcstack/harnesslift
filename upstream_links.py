"""Read-only, bounded associations between proxy UUIDs and short access tags.

UUIDs are internal matching keys. Only fixed categories and permitted numeric
metadata leave summarize(). No network or account operation is performed.
"""

from collections import Counter, deque
from datetime import datetime
from pathlib import Path
import re

import diagnostics


UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
LINK = re.compile(
    r"codex upstream link observation: run=([a-f0-9]{16}) attempt=([1-9]\d{0,19}) "
    r"route=(responses|compact|other) status=(\d{1,3}) "
    r"trace_state=(uuid|absent|multiple|invalid|unavailable) "
    r"upstream_request=(none|" + UUID + r")$")
TAG = re.compile(r"^\[([^]]+)\]\s+\[([a-f0-9]{8})\]")
ROUTES = {"responses": "/v1/responses", "compact": "/v1/responses/compact"}
LIMIT = 256


def link_records(path: Path, since: datetime):
    records = deque(maxlen=LIMIT)
    failures = deque(maxlen=12)
    ordinal = 0
    coverage = {"invalid_records": 0, "records_omitted_at_limit": 0,
                "header_failures_seen": 0, "header_failures_omitted_at_limit": 0}
    for line in diagnostics.lines(path, coverage):
        if "codex upstream link observation:" not in line:
            continue
        prefix = re.match(r"^\[([^]]+)\]", line)
        at = diagnostics.timestamp(prefix[1]) if prefix else None
        if at is not None and at < since:
            continue
        match = LINK.search(line.rstrip("\r\n"))
        if match is None or at is None:
            coverage["invalid_records"] += 1
            continue
        run, attempt, route, status, state, identity = match.groups()
        attempt, status = int(attempt), int(status)
        if (attempt > 2**64 - 1 or status != 0 and not 100 <= status <= 599
                or (state == "uuid") != (identity != "none")
                or state == "uuid" and status == 0):
            coverage["invalid_records"] += 1
            continue
        if len(records) == LIMIT:
            coverage["records_omitted_at_limit"] += 1
        row = {"at": at, "key": (run, attempt), "route": route,
               "status": status, "state": state, "identity": identity, "ordinal": ordinal}
        ordinal += 1
        records.append(row)
        if status >= 400:
            coverage["header_failures_seen"] += 1
            if len(failures) == failures.maxlen:
                coverage["header_failures_omitted_at_limit"] += 1
            failures.append(row)
    # The ordinal deduplicates one retained line, not distinct duplicate lines.
    retained = {row["ordinal"]: row for row in [*records, *failures]}
    return [retained[key] for key in sorted(retained)], coverage


def summarize(origin: Path, managed_logs: list[Path], since: datetime):
    records, scans = [], []
    for path in managed_logs[:32]:
        rows, coverage = link_records(path, since)
        records.extend(rows)
        scans.append(coverage)
    records.sort(key=lambda row: row["at"])
    keys = Counter(row["key"] for row in records)
    identities = Counter(row["identity"] for row in records if row["state"] == "uuid")
    suffixes = Counter(row["identity"][-8:] for row in records if row["state"] == "uuid")
    wanted = set(suffixes)
    matches = {tag: [] for tag in wanted}
    origin_scan = {"invalid_target_timestamps": 0}
    for line in diagnostics.lines(origin, origin_scan):
        tag = TAG.match(line)
        access = diagnostics.GIN.search(line) if tag else None
        if not access or tag[2] not in wanted:
            continue
        at = diagnostics.timestamp(tag[1])
        if at is None:
            origin_scan["invalid_target_timestamps"] += 1
            continue
        if at < since:
            continue
        # Retain at most two matches; even duplicate lines are ambiguous.
        if len(matches[tag[2]]) < 2:
            matches[tag[2]].append({"at": at, "method": access[4],
                "endpoint": diagnostics.endpoint_label(access[5]), "status": int(access[2]),
                "seconds": diagnostics.duration(access[3].strip())})
    incomplete = (len(managed_logs) > 32 or origin_scan.get("oversized_lines", 0) != 0 or
        origin_scan["invalid_target_timestamps"] != 0 or
        any(scan["oversized_lines"] or scan["invalid_records"] or scan["records_omitted_at_limit"] for scan in scans))
    recent_indices = list(range(max(0, len(records) - 12), len(records)))
    failure_indices = [index for index, row in enumerate(records) if row["status"] >= 400][-12:]
    result = {}
    for index in sorted(set(recent_indices + failure_indices)):
        row = records[index]
        candidate, kind = None, "unavailable"
        if row["state"] == "uuid":
            hits = matches[row["identity"][-8:]]
            if incomplete:
                kind = "coverage_limited"
            elif keys[row["key"]] != 1 or identities[row["identity"]] != 1 or suffixes[row["identity"][-8:]] != 1 or len(hits) > 1:
                kind = "ambiguous"
            elif not hits:
                kind = "unmatched"
            else:
                hit = hits[0]
                if (hit["method"] != "POST" or hit["endpoint"] != ROUTES.get(row["route"])
                        or hit["status"] != row["status"]):
                    kind = "inconsistent"
                else:
                    kind = "unique_tag_candidate"
                    candidate = {"status": hit["status"], "seconds": hit["seconds"]}
        result[index] = {"at": row["at"].isoformat(), "route": row["route"],
            "status": row["status"], "trace_state": row["state"],
            "origin_tag_match": kind, "origin_candidate": candidate}
    return {"read_only": True, "records_observed": bool(records),
        "recent": [result[index] for index in recent_indices],
        "recent_header_failures": [result[index] for index in failure_indices],
        "header_failures_omitted_at_limit": max(0, sum(scan["header_failures_seen"] for scan in scans) - len(failure_indices)),
        "attempt_records_omitted_at_limit": sum(scan["records_omitted_at_limit"] for scan in scans),
        "invalid_records": sum(scan["invalid_records"] for scan in scans),
        "records_omitted_from_recent": max(0, len(records) - 12),
        "managed_logs_omitted": max(0, len(managed_logs) - 32),
        "coverage_limited": incomplete,
        "limits": "A unique 32-bit log tag is a candidate association, not an exact cross-layer identity. "
            "Missing, rotated or unobserved records can hide collisions. Header arrival is not stream completion; "
            "the retained header failures do not include every later stream failure. Missing records cannot establish header absence. "
            "This proxy trace is not an OpenAI request ID, account binding, replay permission or a root-cause diagnosis."}
