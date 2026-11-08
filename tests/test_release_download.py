"""Pinned-download fallback, HTTPS and privacy controls using owned bytes."""

import hashlib
import io
import os
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import install
import pinned_download as transport


PAYLOAD = b"owned-synthetic-release"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
PRIVATE = "SYNTHETIC_PRIVATE_DOWNLOAD_CREDENTIAL"


class ReleaseDownloadTests(unittest.TestCase):
    def run_archive(self, replies, *, existing=None, limit=None):
        self.requests = []
        self.contexts = []

        class Opener:
            def open(_self, request, **kwargs):
                self.requests.append(request)
                self.assertEqual(kwargs, {"timeout": 60})
                reply = replies[len(self.requests) - 1]
                if isinstance(reply, BaseException):
                    raise reply
                return io.BytesIO(reply) if isinstance(reply, bytes) else reply

        def builder(*handlers):
            tls = next(handler for handler in handlers if isinstance(handler, urllib.request.HTTPSHandler))
            self.contexts.append(tls._context)
            self.assertTrue(any(isinstance(handler, transport.HTTPSReleaseRedirect) for handler in handlers))
            return Opener()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / f"CLIProxyAPI_{install.VERSION}_windows_amd64.zip"
            if existing is not None:
                archive.write_bytes(existing)
            with patch.object(install.platform, "system", return_value="Windows"), \
                 patch.object(install.platform, "machine", return_value="AMD64"), \
                 patch.object(install, "ASSETS", {("Windows", "x86_64"): ("windows_amd64", DIGEST)}), \
                 patch.object(install, "ASSET_API_IDS", {("Windows", "x86_64"): 17}), \
                 patch.object(transport.urllib.request, "build_opener", side_effect=builder), \
                 patch.dict(os.environ, {"GITHUB_TOKEN": PRIVATE, "OPENAI_API_KEY": PRIVATE,
                     "SSLKEYLOGFILE": str(root / "must-not-exist")}), \
                 patch.object(transport, "MAX_ARCHIVE_BYTES", limit or transport.MAX_ARCHIVE_BYTES):
                try:
                    result = install.verified_archive(root, None)
                    self.assertEqual(result.read_bytes(), PAYLOAD)
                    self.assertFalse((root / "must-not-exist").exists())
                    return True
                finally:
                    self.remaining_archive = archive.read_bytes() if archive.exists() else None
                    self.temporary_files = list(root.glob("download-*"))

    def test_primary_success_and_cached_success_use_no_extra_request(self):
        self.assertTrue(self.run_archive([PAYLOAD]))
        self.assertEqual(len(self.requests), 1)
        self.assertFalse(self.temporary_files)
        self.assertTrue(self.run_archive([], existing=PAYLOAD))
        self.assertFalse(self.requests)

    def test_gateway_refusal_uses_one_official_api_request_with_no_credentials(self):
        for code in (502, 503, 504):
            error = urllib.error.HTTPError("https://example.invalid/", code, "Owned refusal", {}, io.BytesIO())
            self.assertTrue(self.run_archive([error, PAYLOAD]))
            self.assertEqual(len(self.requests), 2)
            request = self.requests[1]
            self.assertEqual(request.full_url, "https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/assets/17")
            self.assertEqual(request.get_header("Accept"), "application/octet-stream")
            for req in self.requests:
                self.assertIsNone(req.get_header("Authorization"))
                self.assertIsNone(req.get_header("Cookie"))
                self.assertNotIn(PRIVATE, repr(req.headers))
            self.assertTrue(error.fp.closed)
            self.assertFalse(self.temporary_files)
            for context in self.contexts:
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                self.assertIsNone(context.keylog_filename)
                if sys.version_info >= (3, 13):
                    flags = ssl.VERIFY_X509_PARTIAL_CHAIN | ssl.VERIFY_X509_STRICT
                    self.assertEqual(context.verify_flags & flags, flags)

    def test_auth_rate_limit_and_other_http_errors_do_not_fall_back(self):
        for code in (401, 403, 404, 429, 500):
            error = urllib.error.HTTPError("https://example.invalid/", code, PRIVATE, {}, io.BytesIO())
            with self.assertRaisesRegex(RuntimeError, f"HTTP {code}") as failure:
                self.run_archive([error])
            self.assertNotIn(PRIVATE, str(failure.exception))
            self.assertEqual(len(self.requests), 1)
            self.assertTrue(error.fp.closed)

    def test_tls_or_transport_error_does_not_try_another_endpoint(self):
        for error in (urllib.error.URLError(PRIVATE), ssl.SSLCertVerificationError(PRIVATE),
                      urllib.error.URLError(ssl.SSLCertVerificationError(PRIVATE)),
                      urllib.error.URLError("timed out " + PRIVATE)):
            with self.subTest(error=type(error).__name__), self.assertRaisesRegex(RuntimeError, "TLS or transport") as failure:
                self.run_archive([error])
            self.assertNotIn(PRIVATE, str(failure.exception))
            self.assertEqual(len(self.requests), 1)

    def test_typed_connection_and_body_timeouts_allow_one_pinned_alternate(self):
        class InterruptedBody(io.BytesIO):
            def __init__(self):
                super().__init__(b"owned-partial-body")
                self.reads = 0

            def read(self, size=-1):
                self.reads += 1
                if self.reads > 1:
                    raise TimeoutError(PRIVATE)
                return super().read(size)

        for error in (TimeoutError(PRIVATE), urllib.error.URLError(TimeoutError(PRIVATE))):
            with self.subTest(error=type(error).__name__):
                self.assertTrue(self.run_archive([error, PAYLOAD], existing=b"retain-owned-file"))
                self.assertEqual(len(self.requests), 2)
                self.assertFalse(self.temporary_files)
        body = InterruptedBody()
        self.assertTrue(self.run_archive([body, PAYLOAD], existing=b"retain-owned-file"))
        self.assertTrue(body.closed)
        self.assertFalse(self.temporary_files)
        self.assertEqual(len(self.requests), 2)

    def test_alternate_timeout_never_loops_or_replaces_cached_bytes(self):
        for error in (TimeoutError(PRIVATE), urllib.error.URLError(TimeoutError(PRIVATE))):
            with self.subTest(error=type(error).__name__), self.assertRaisesRegex(RuntimeError, "timeout|transport") as failure:
                self.run_archive([TimeoutError(PRIVATE), error], existing=b"retain-owned-file")
            self.assertNotIn(PRIVATE, str(failure.exception))
            self.assertEqual(len(self.requests), 2)
            self.assertEqual(self.remaining_archive, b"retain-owned-file")
            self.assertFalse(self.temporary_files)

    def test_timeout_without_a_reviewed_alternate_fails_once(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(transport, "download_release", side_effect=TimeoutError(PRIVATE)) as download:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "network timeout") as failure:
                transport.download_with_api_fallback(root, root / "owned.zip", "https://github.com/owned", None, DIGEST)
            self.assertNotIn(PRIVATE, str(failure.exception))
            self.assertEqual(download.call_count, 1)

    def test_changed_or_oversized_bytes_never_replace_cached_bytes(self):
        for payload, limit in ((b"changed", None), (PAYLOAD, 3)):
            with self.assertRaises(RuntimeError):
                self.run_archive([payload], existing=b"retain-owned-file", limit=limit)
            self.assertEqual(self.remaining_archive, b"retain-owned-file")
            self.assertFalse(self.temporary_files)
            self.assertEqual(len(self.requests), 1)

    def test_failed_api_attempt_is_bounded_and_does_not_publish_unverified_bytes(self):
        refusal = urllib.error.HTTPError("https://example.invalid/", 504, "Owned refusal", {}, io.BytesIO())
        with self.assertRaisesRegex(RuntimeError, "SHA-256"):
            self.run_archive([refusal, b"changed"], existing=b"retain-owned-file")
        self.assertEqual(self.remaining_archive, b"retain-owned-file")
        self.assertFalse(self.temporary_files)
        self.assertEqual(len(self.requests), 2)

    def test_https_redirects_preserve_the_request_and_refuse_downgrades_or_userinfo(self):
        handler = transport.HTTPSReleaseRedirect()
        request = urllib.request.Request("https://github.com/owned", headers={"Accept": "application/octet-stream"})
        valid = handler.redirect_request(request, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/owned")
        self.assertEqual(valid.get_header("Accept"), "application/octet-stream")
        for url in ("http://example.invalid/", "file:///owned", "https://alice:owned@example.invalid/", "https:///"):
            with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                handler.redirect_request(request, None, 302, "Found", {}, url)

    def test_all_pinned_platforms_have_an_official_api_asset_id(self):
        self.assertEqual(set(install.ASSETS), set(install.ASSET_API_IDS))
        self.assertTrue(all(type(value) is int and value > 0 for value in install.ASSET_API_IDS.values()))

    def test_shared_download_refuses_a_symlink_cache_before_network_io(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(Path, "is_symlink", return_value=True), \
             patch.object(transport.urllib.request, "build_opener") as opener:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "symlinked"):
                transport.download_release(root, root / "owned.zip", "https://example.invalid/owned", DIGEST)
            opener.assert_not_called()

    def test_caller_cannot_raise_the_global_download_bound(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(transport.urllib.request, "build_opener") as opener:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "limit"):
                transport.download_release(root, root / "owned.zip", "https://example.invalid/owned", DIGEST,
                                           max_bytes=transport.MAX_ARCHIVE_BYTES + 1)
            opener.assert_not_called()

    def test_alternate_url_cannot_select_a_mirror_or_embed_a_credential(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(transport, "download_release") as download:
            root = Path(temporary)
            for alternate in ("https://mirror.invalid/owned", "http://api.github.com/repos/a/b/releases/assets/17",
                    "https://api.github.com/repos/a/b/releases/assets/17?token=" + PRIVATE,
                    "https://alice:owned@api.github.com/repos/a/b/releases/assets/17"):
                with self.assertRaisesRegex(RuntimeError, "official asset API") as error:
                    transport.download_with_api_fallback(root, root / "owned.zip", "https://github.com/owned", alternate, DIGEST)
                self.assertNotIn(PRIVATE, str(error.exception))
            download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
