"""Privacy, collision and incomplete-coverage controls for owned trace logs."""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from tests import trace_link_fixture as fixture


SINCE = datetime(2026, 1, 1, tzinfo=timezone.utc)
UUID = "01950000-0000-7000-8000-1234aabbccdd"
RUN = "1234567890abcdef"


def observation(*, identity=UUID, attempt=1, state="uuid", status=200, **changes):
    fields = {"run": RUN, "attempt": attempt, "route": "responses", "status": status,
              "trace_state": state, "upstream_request": identity}
    fields.update(changes)
    return "[2026-01-02T12:00:00Z] [a1b2c3d4] [info] codex upstream link observation: " + " ".join(
        f"{key}={value}" for key, value in fields.items()) + "\n"


def access(**changes):
    fields = {"tag": "aabbccdd", "status": 200, "method": "POST", "path": "/v1/responses", "at": "12:00:01"}
    fields.update(changes)
    return (f'[2026-01-02T{fields["at"]}Z] [{fields["tag"]}] [info] [gin.go:1] '
            f'{fields["status"]} | 2.5s | PRIVATE_HOST | {fields["method"]} "{fields["path"]}"\n')


def summary(origin, *backends):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        inner = root / "PRIVATE_ORIGIN.log"
        inner.write_text(origin, encoding="utf-8")
        paths = []
        for index, body in enumerate(backends):
            path = root / f"PRIVATE_MANAGED_{index}.log"
            path.write_text(body, encoding="utf-8")
            paths.append(path)
        return fixture.summarize(inner, paths, SINCE)


class TraceLinkFixtureTests(unittest.TestCase):
    def test_candidate_is_not_in_the_selected_bundle(self):
        import runtime_bundle
        self.assertNotIn("codex-upstream-link-candidate.patch", runtime_bundle.PATCHES)

    def test_unique_candidate_keeps_only_fixed_metadata(self):
        report = summary(access(path="/v1/responses?token=PRIVATE_SECRET"), observation())
        row, = report["recent"]
        self.assertEqual(row["origin_tag_match"], "unique_tag_candidate")
        self.assertEqual(row["origin_candidate"], {"status": 200, "seconds": 2.5})
        for private in (UUID, RUN, "aabbccdd", "a1b2c3d4", "PRIVATE", "attempt", "upstream_request"):
            self.assertNotIn(private, json.dumps(report))
        self.assertIn("not an exact cross-layer identity", report["limits"])

    def test_duplicate_access_or_attempts_and_observed_suffix_collisions_are_ambiguous(self):
        other = UUID.replace("01950000", "01950001")
        for inner, backends in (
                (access() * 2, [observation()]),
                (access(), [observation() * 2]),
                (access(), [observation(), observation()]),
                (access(), [observation() + observation(identity=other, attempt=2)]),
                (access(), [observation() + observation(attempt=2)])):
            with self.subTest(backends=len(backends)):
                report = summary(inner, *backends)
                self.assertTrue(all(row["origin_tag_match"] == "ambiguous" for row in report["recent"]))
                self.assertTrue(all(row["origin_candidate"] is None for row in report["recent"]))

    def test_missing_or_changed_trace_never_guesses_by_time(self):
        for state in ("absent", "multiple", "invalid", "unavailable"):
            row, = summary(access(), observation(state=state, identity="none"))["recent"]
            self.assertEqual(row["origin_tag_match"], "unavailable")
        row, = summary(access(tag="11223344"), observation())["recent"]
        self.assertEqual(row["origin_tag_match"], "unmatched")
        for change in ({"status": 503}, {"method": "GET"}, {"path": "/v1/messages"}, {"at": "11:59:59"}):
            row, = summary(access(**change), observation())["recent"]
            self.assertEqual(row["origin_tag_match"], "inconsistent")
            self.assertIsNone(row["origin_candidate"])

    def test_invalid_unbounded_or_skipped_records_withhold_associations(self):
        for bad in (observation(attempt=2**64), observation(state="PRIVATE_SECRET"),
                    observation(identity="none"), observation(status=999),
                    observation().rstrip() + " PRIVATE_SECRET\n",
                    "[2026-01-02T12:00:00Z] " + "x" * (2 * 1024 * 1024) + "\n"):
            report = summary(access(), bad + observation())
            self.assertTrue(report["coverage_limited"])
            row, = report["recent"]
            self.assertEqual(row["origin_tag_match"], "coverage_limited")
            self.assertNotIn("PRIVATE", json.dumps(report))
        report = summary(access(), "".join(observation(attempt=i) for i in range(1, 258)))
        self.assertTrue(report["coverage_limited"])
        self.assertEqual(len(report["recent"]), 12)
        self.assertEqual(report["records_omitted_from_recent"], 244)
        self.assertTrue(all(row["origin_tag_match"] == "coverage_limited" for row in report["recent"]))

    def test_window_and_logs_limit_are_explicit(self):
        old = observation().replace("2026-01-02", "2025-12-31")
        self.assertFalse(summary(access(), old)["recent"])
        report = summary(access(), *[observation(attempt=i) for i in range(1, 34)])
        self.assertEqual(report["managed_logs_omitted"], 1)
        self.assertTrue(report["coverage_limited"])
        report = summary(access().replace("2026-01-02", "2025-12-31"), observation())
        self.assertEqual(report["recent"][0]["origin_tag_match"], "unmatched")


if __name__ == "__main__":
    unittest.main()
