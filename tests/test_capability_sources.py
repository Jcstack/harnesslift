"""Historical capability snapshots stay complete, immutable and isolated."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import capabilities
import runtime_bundle


def snapshot(root, sources, replacement=None):
    runtime_bundle.private_dir(root)
    for name in sources:
        runtime_bundle.write_file(root / name, (replacement or {}).get(name, b"# owned source fixture\n"), 0o700)
    lock = "a" * 64
    with patch.object(capabilities, "SERVER_SOURCES", sources):
        identity = capabilities.freeze_server(root, lock)
    runtime_bundle.write_file(root / "capabilities.json", runtime_bundle.canonical(
        {"format": 1, "enabled": True, "lock": lock, "server": identity}), 0o600)
    return identity


class CapabilitySourceTests(unittest.TestCase):
    def test_complete_historical_and_current_snapshots_remain_readable(self):
        for profile in (capabilities.LEGACY_SERVER_SOURCES, capabilities.MODEL_HELPER_SERVER_SOURCES,
                        capabilities.SERVER_SOURCES):
            with self.subTest(profile=len(profile)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                identity = snapshot(root, profile)
                original = (root / "capabilities" / "servers" / identity / "bundle.json").read_bytes()
                self.assertTrue(capabilities.selected_server(root).is_file())
                self.assertEqual((root / "capabilities" / "servers" / identity / "bundle.json").read_bytes(), original)

    def test_new_import_cannot_fall_through_to_workspace_or_external_pythonpath(self):
        for name, body in (("desktop_adapter.py", b"import pinned_download\n"),
                           ("native_services.py", b"from pinned_download import download_release\n"),
                           ("launcher.py", b"from pinned_download.future import helper\n")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                snapshot(root, capabilities.MODEL_HELPER_SERVER_SOURCES, {name: body})
                runtime_bundle.write_file(root / "pinned_download.py", b"# outside the immutable snapshot\n", 0o700)
                with self.assertRaisesRegex(RuntimeError, "missing a required archive download helper"):
                    capabilities.selected_server(root)

    def test_unknown_legacy_dependency_state_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot(root, capabilities.MODEL_HELPER_SERVER_SOURCES, {"desktop_adapter.py": b"not valid Python !!!\n"})
            with self.assertRaisesRegex(RuntimeError, "cannot be verified"):
                capabilities.selected_server(root)

if __name__ == "__main__":
    unittest.main()
