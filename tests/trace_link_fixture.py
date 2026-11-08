"""Bounded, private accounting for the unselected upstream-link candidate.

UUIDs are internal matching keys. Only fixed categories and permitted numeric
metadata leave summarize(); this fixture is not installed by the launcher.
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
    coverage = {"invalid_records": 0, "records_omitted_at_limit": 0}
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
        records.append({"at": at, "key": (run, attempt), "route": route,
                        "status": status, "state": state, "identity": identity})
    return list(records), coverage


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
    origin_scan = {}
    for line in diagnostics.lines(origin, origin_scan):
        tag = TAG.match(line)
        access = diagnostics.GIN.search(line) if tag else None
        if not access or tag[2] not in wanted:
            continue
        at = diagnostics.timestamp(tag[1])
        if at is None or at < since:
            continue
        # Retain at most two matches; even duplicate lines are ambiguous.
        if len(matches[tag[2]]) < 2:
            matches[tag[2]].append({"at": at, "method": access[4],
                "endpoint": diagnostics.endpoint_label(access[5]), "status": int(access[2]),
                "seconds": diagnostics.duration(access[3].strip())})
    incomplete = (len(managed_logs) > 32 or origin_scan.get("oversized_lines", 0) != 0 or
        any(scan["oversized_lines"] or scan["invalid_records"] or scan["records_omitted_at_limit"] for scan in scans))
    result = []
    for row in records[-12:]:
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
                        or hit["status"] != row["status"] or hit["at"] < row["at"].replace(microsecond=0)):
                    kind = "inconsistent"
                else:
                    kind = "unique_tag_candidate"
                    candidate = {"status": hit["status"], "seconds": hit["seconds"]}
        result.append({"at": row["at"].isoformat(), "route": row["route"],
            "status": row["status"], "trace_state": row["state"],
            "origin_tag_match": kind, "origin_candidate": candidate})
    return {"synthetic_candidate_only": True, "recent": result,
        "records_omitted_from_recent": max(0, len(records) - 12),
        "managed_logs_omitted": max(0, len(managed_logs) - 32),
        "coverage_limited": incomplete,
        "limits": "A unique 32-bit log tag is a candidate association, not an exact cross-layer identity. "
            "Missing, rotated or unobserved records can hide collisions. Header arrival is not stream completion. "
            "This proxy trace is not an OpenAI request ID, account binding, replay permission or a root-cause diagnosis."}
