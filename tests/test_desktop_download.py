"""Exercise desktop bootstrap pins and limits without launching an app."""

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import desktop_adapter
import desktop_scope


class DesktopDownloadTests(unittest.TestCase):
    def test_shared_transport_retains_the_archive_pin_binary_pin_and_original_size_bound(self):
        name = "windows/amd64/open-computer-use.exe"
        binary = b"owned-desktop-fixture-do-not-run"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo("package/dist/" + name)
            info.size = len(binary)
            archive.addfile(info, io.BytesIO(binary))
        payload = buffer.getvalue()
        digest = hashlib.sha256(payload).hexdigest()

        def download(root, destination, primary, alternate, expected, **options):
            self.assertEqual(expected, digest)
            self.assertEqual(options, {"max_bytes": 32 << 20})
            self.assertEqual(primary, desktop_adapter.ARCHIVE_URL)
            self.assertEqual(alternate, desktop_adapter.ARCHIVE_API_URL)
            destination.write_bytes(payload)

        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(desktop_adapter.runtime_bundle, "target", return_value="windows-x86_64"), \
             patch.object(desktop_adapter, "BINARIES", {"windows-x86_64": (name, hashlib.sha256(binary).hexdigest())}), \
             patch.object(desktop_adapter, "ARCHIVE_SHA", digest), \
             patch.object(desktop_adapter.pinned_download, "download_with_api_fallback", side_effect=download) as fetch:
            root = Path(temporary)
            desktop_adapter.install(root)
            self.assertEqual(desktop_adapter.executable(root).read_bytes(), binary)
            self.assertFalse((root / "desktop.json").exists())
            desktop_adapter.install(root)
            self.assertEqual(fetch.call_count, 1)

    def test_failed_download_does_not_extract_a_binary_or_select_a_window(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(desktop_adapter.runtime_bundle, "target", return_value="windows-x86_64"), \
             patch.object(desktop_adapter.pinned_download, "download_with_api_fallback", side_effect=RuntimeError("Owned download refusal")):
            root = Path(temporary)
            with self.assertRaisesRegex(desktop_scope.ScopeError, "Owned download refusal"):
                desktop_adapter.install(root)
            self.assertFalse((root / "desktop" / desktop_adapter.VERSION).exists())
            self.assertFalse((root / "desktop.json").exists())


if __name__ == "__main__":
    unittest.main()
