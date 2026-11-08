"""Observe private trace links through owned mixed-version proxies and TLS.

Only disposable API-key fixtures and local fake responses are used. The tap
holds complete synthetic bodies; its timings are not provider measurements.
No installed runtime, account, active terminal or user session is accessed.
"""

import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import api_profile
import launcher
import runtime_bundle
from claude_fixture import isolated_environment
from codex_stream_fixture import temporary_codex_translator
from probe_http_phases import response_bytes, MARKER
from probe_tls_initialization import tls_failure_metadata
from trace_link_fixture import link_records, summarize, UUID


SINCE = datetime(2020, 1, 1, tzinfo=timezone.utc)
PRIVATE = "SYNTHETIC_PRIVATE_TRACE_HEADER"
UUID_SHAPE = re.compile(UUID)


def request_uuid(value):
    """Only used with owned proxy headers, in memory, never printed."""
    tail = value[-36:]
    if not UUID_SHAPE.fullmatch(tail):
        raise AssertionError("Owned proxy did not return a UUIDv7 trace")
    return tail


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        with self.server.lock:
            self.server.calls += 1
            mode = self.server.mode
        if mode == "refusal":
            payload = b'{"error":{"type":"server_error","message":"Owned refusal"}}'
        elif mode == "eof":
            payload = (b'data: {"type":"response.created","response":{"id":"fixture","model":"gpt-6.1-sol"}}\n\n'
                       b'data: {"type":"response.output_item.done","output_index":0,"item":{"type":"reasoning",'
                       b'"id":"fixture-reasoning","summary":[],"encrypted_content":"owned"}}\n\n')
        else:
            payload = response_bytes(body.get("model"))
        self.send_response(503 if mode == "refusal" else 200)
        self.send_header("Content-Type", "application/json" if mode == "refusal" else "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True


class Tap(BaseHTTPRequestHandler):
    """Forward to the disposable inner proxy and alter only its trace header."""

    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        connection = http.client.HTTPConnection("127.0.0.1", self.server.origin_port, timeout=15)
        try:
            connection.request("POST", self.path, body,
                {"Authorization": "Bearer " + self.server.origin_key, "Content-Type": "application/json"})
            response = connection.getresponse()
            trace_values = response.headers.get_all("X-CPA-TRACE-ID", [])
            if len(trace_values) != 1:
                raise AssertionError("Owned inner proxy trace was missing or duplicated")
            identity = request_uuid(trace_values[0])
            payload = response.read(1024 * 1024 + 1)
            if len(payload) > 1024 * 1024:
                raise AssertionError("Owned upstream response exceeded the fixture bound")
            with self.server.lock:
                mode = self.server.mode
                self.server.records.append({"identity": identity, "trace": trace_values[0], "mode": mode})
            self.send_response(response.status)
            self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(payload)))
            if mode in ("valid", "multiple"):
                self.send_header("X-CPA-TRACE-ID", trace_values[0])
                if mode == "multiple":
                    self.send_header("X-CPA-TRACE-ID", trace_values[0])
            elif mode == "invalid":
                self.send_header("X-CPA-TRACE-ID", PRIVATE)
            elif mode == "comma":
                self.send_header("X-CPA-TRACE-ID", ",".join(trace_values * 2))
            self.end_headers()
            self.wfile.write(payload)
        except (OSError, ValueError, AssertionError, http.client.HTTPException):
            with self.server.lock:
                self.server.failed = True
            self.close_connection = True
        finally:
            connection.close()


@contextmanager
def local_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.lock = threading.Lock()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def tls_ingress(binary, backend_port, backend_key):
    with tempfile.TemporaryDirectory(prefix="bridge-private-trace-link-") as temporary:
        root = Path(temporary)
        runtime_bundle.private_dir(root)
        environment = isolated_environment(root)
        result = subprocess.run([str(binary), "--root", str(root), "--init-tls"],
            env=environment, capture_output=True, timeout=20)
        if result.returncode:
            print(json.dumps({"synthetic_tls_bootstrap": tls_failure_metadata(result)}))
            raise RuntimeError("Owned TLS initialization failed")
        owners = launcher.listener_pids(backend_port)
        if len(owners) != 1:
            raise RuntimeError("Owned backend identity was ambiguous")
        backend_file, front_file, manifest = root / "backend-key", root / "front-key", root / "backend.json"
        api_profile.write_private(backend_file, backend_key)
        api_profile.write_private(front_file, "b" * 64)
        api_profile.write_private(manifest, json.dumps({"generation": "fixture-trace-link", "port": backend_port,
            "pid": next(iter(owners)), "key_file": str(backend_file)}))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([str(binary), "--root", str(root), "--listen", f"127.0.0.1:{port}",
            "--backend-file", str(manifest), "--key-file", str(front_file), "--tls"], cwd=root, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            launcher.wait_for_private_listener(process, port)
            yield port, "b" * 64, ssl.create_default_context(cafile=str(root / "ca.pem"))
        finally:
            launcher.stop_process(process)


def call(port, key, context, *, stream):
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=20, context=context)
    try:
        body = {"model": "gpt-6.1-sol", "stream": stream, "max_tokens": 64,
                "messages": [{"role": "user", "content": "OWNED_TRACE_LINK_CONTROL"}]}
        connection.request("POST", "/v1/messages", json.dumps(body), {"Authorization": "Bearer " + key,
            "Content-Type": "application/json", "X-CPA-TRACE-ID": PRIVATE})
        response = connection.getresponse()
        trace = response.headers.get_all("X-CPA-TRACE-ID", [])
        payload = response.read(1024 * 1024 + 1)
        assert len(payload) <= 1024 * 1024, "Owned client response exceeded its bound"
        assert len(trace) == 1 and PRIVATE not in trace[0], "Caller-controlled trace was trusted"
        return response.status, payload, request_uuid(trace[0])
    finally:
        connection.close()


def wait_records(path, expected):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        records, coverage = link_records(path, SINCE)
        if len(records) == expected:
            assert not coverage["invalid_records"], "Candidate emitted invalid link metadata"
            return records
        threading.Event().wait(.05)
    raise RuntimeError("Owned candidate link observations were missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin_binary", type=Path)
    parser.add_argument("candidate_binary", type=Path)
    parser.add_argument("ingress_binary", type=Path)
    args = parser.parse_args()
    cases = []
    with ExitStack() as stack:
        provider = stack.enter_context(local_server(Provider))
        provider.calls, provider.mode = 0, "healthy"
        origin_port, origin_key, origin_log = stack.enter_context(temporary_codex_translator(
            args.origin_binary.resolve(), provider.server_port, managed_policy=True))
        tap = stack.enter_context(local_server(Tap))
        tap.origin_port, tap.origin_key, tap.mode, tap.records, tap.failed = origin_port, origin_key, "valid", [], False
        port, key, candidate_log = stack.enter_context(temporary_codex_translator(
            args.candidate_binary.resolve(), tap.server_port, upstream_prefix="/v1",
            upstream_key="fixture-local", local_key="a" * 64, managed_policy=True))
        front_port, front_key, context = stack.enter_context(tls_ingress(args.ingress_binary.resolve(), port, key))
        count = 0
        for provider_mode, header_mode, stream in (
                ("healthy", "valid", True), ("healthy", "valid", False),
                ("eof", "valid", True), ("refusal", "valid", False),
                ("healthy", "absent", True), ("healthy", "multiple", True),
                ("healthy", "invalid", False), ("healthy", "comma", False)):
            provider.mode, tap.mode = provider_mode, header_mode
            status, payload, outer_uuid = call(front_port, front_key, context, stream=stream)
            count += 1
            records = wait_records(candidate_log, count)
            observed, actual = records[-1], tap.records[-1]
            assert not tap.failed and provider.calls == count, "Observation added or lost an upstream request"
            assert actual["identity"] != outer_uuid, "The outer response trace was mistaken for the inner trace"
            expected_state = {"valid": "uuid", "absent": "absent", "multiple": "multiple",
                              "invalid": "invalid", "comma": "invalid"}[header_mode]
            assert observed["state"] == expected_state, "Trace presence was guessed"
            if header_mode == "valid":
                assert observed["identity"] == actual["identity"], "The immediate-upstream request UUID was lost"
            else:
                assert observed["identity"] == "none", "An unusable trace produced a request identity"
            if provider_mode == "healthy":
                assert status == 200 and MARKER.encode() in payload, "Healthy synthetic content changed"
                if stream:
                    assert b"event: message_stop" in payload, "Healthy stream completion disappeared"
                else:
                    assert json.loads(payload).get("stop_reason") == "end_turn", "Healthy buffered completion changed"
            elif provider_mode == "eof":
                assert b"event: error" in payload and b"event: message_stop" not in payload, "Incomplete stream was concealed"
            else:
                assert status == 503, "Owned refusal status changed"
            cases.append({"provider": provider_mode, "header": header_mode, "stream": stream,
                          "private_link_observed": True, "one_provider_attempt": True})
        provider.mode, tap.mode = "healthy", "valid"
        parallel, errors = [], []

        def concurrent_call():
            try:
                parallel.append(call(front_port, front_key, context, stream=True))
            except (OSError, ValueError, AssertionError, http.client.HTTPException):
                errors.append(True)

        workers = [threading.Thread(target=concurrent_call) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=25)
        assert not errors and all(not worker.is_alive() for worker in workers) and len(parallel) == 2, "Concurrent owned controls failed"
        assert all(status == 200 and MARKER.encode() in payload for status, payload, _identity in parallel), "Concurrent content changed"
        count += 2
        records = wait_records(candidate_log, count)
        assert len({row["identity"] for row in records[-2:]}) == 2, "Concurrent request identities were merged"
        assert {row["identity"] for row in records[-2:]} == {row["identity"] for row in tap.records[-2:]}, "Concurrent links crossed requests"
        assert provider.calls == count and not tap.failed, "Concurrent observation added a request"
        # Wait for owned access records; returned headers alone are not completion.
        deadline = time.monotonic() + 10
        while True:
            report = summarize(origin_log, [candidate_log], SINCE)
            valid = [row for row in report["recent"] if row["trace_state"] == "uuid"]
            if all(row["origin_tag_match"] == "unique_tag_candidate" for row in valid):
                break
            if time.monotonic() >= deadline:
                raise AssertionError("Owned origin access records did not yield unique tag candidates")
            threading.Event().wait(.05)
        link_lines = "\n".join(line for line in candidate_log.read_text(encoding="utf-8").splitlines()
                               if "codex upstream link observation:" in line)
        for row in tap.records:
            assert row["trace"][:-36] not in link_lines, "Credential-selection trace prefix escaped"
            assert row["identity"] not in json.dumps(report), "Raw request identity escaped the summary"
        assert PRIVATE not in candidate_log.read_text(encoding="utf-8"), "Private header value escaped"
        print(json.dumps({"synthetic_only": True, "managed_tls_path": True, "cases": cases,
            "concurrent_links_distinct": True, "outer_trace_not_inner_trace": True,
            "caller_trace_ignored": True, "no_added_upstream_requests": True,
            "selection_prefix_absent": True, "private_summary": True,
            "origin_matches_are_candidates_only": True}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, AssertionError, subprocess.SubprocessError, http.client.HTTPException):
        raise SystemExit("Owned upstream trace-link gate failed; raw details withheld") from None
