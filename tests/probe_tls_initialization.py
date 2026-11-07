"""Exercise owned TLS bootstrap and report only fixed failure metadata.

Temporary keys stay in disposable private directories. No account, model,
existing service, raw subprocess output, SID or local path is reported.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rolling_runtime
import runtime_bundle
import windows_acl


def tls_failure_metadata(result):
    raw = (result.stderr or b"") + (result.stdout or b"")
    text = raw.decode("utf-8", errors="replace").lower()
    code = re.search(r"runtime ntfs acl verification failed \(check (-?\d+)\)", text)
    number = int(code.group(1)) if code else None
    return {"returncode": result.returncode,
        "acl_check_code": number if number in (-1, 21, 22, 23, 24) else None,
        "failure_classes": [label for label, needles in (
            ("private_directory", ("private runtime directory required", "runtime directory must have mode")),
            ("ntfs_acl", ("runtime ntfs acl",)),
            ("incomplete_ca", ("incomplete local ca",)),
            ("invalid_ca", ("invalid local ca pair", "local ca invalid or nearing expiry")),
            ("unsafe_path", ("symlink", "outside runtime", "path escapes")),
            ("file_access", ("access is denied", "permission denied", "sharing violation")),
            ("powershell_method", ("methodinvocationexception", "methodnotfound")),
            ("powershell_access", ("unauthorizedaccessexception",)),
        ) if any(needle in text for needle in needles)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ingress", type=Path)
    args = parser.parse_args()
    binary = args.ingress.resolve()
    if not binary.is_file():
        raise SystemExit("Owned ingress binary is missing")
    results = []
    with tempfile.TemporaryDirectory(prefix="bridge-tls-bootstrap-") as temporary:
        parent = Path(temporary)
        runtime_bundle.private_dir(parent)
        for name in ("private-first", "private-second", "unsafe"):
            root = parent / name
            runtime_bundle.private_dir(root)
            safe = name != "unsafe"
            if not safe:
                if os.name == "nt":
                    windows_acl.run_icacls(str(root), "/grant", "*S-1-1-0:(OI)(CI)R")
                else:
                    root.chmod(0o755)
            run = subprocess.run([str(binary), "--root", str(root), "--init-tls"],
                cwd=root, env=rolling_runtime.process_environment(), capture_output=True, timeout=20)
            row = {"synthetic_only": True, "case": name, **tls_failure_metadata(run),
                   "all_certificate_files_present": all((root / file).is_file() for file in
                       ("ca.pem", "ca-key.pem", "server.pem", "server-key.pem")),
                   "any_certificate_file_present": any(root.glob("*.pem"))}
            print(json.dumps(row), flush=True)
            if safe and (run.returncode != 0 or not row["all_certificate_files_present"]):
                raise SystemExit("Owned TLS bootstrap failed; raw output withheld")
            if not safe and (run.returncode == 0 or row["any_certificate_file_present"]):
                raise SystemExit("Unsafe owned directory was accepted or received certificate material")
            results.append(row)
    print(json.dumps({"synthetic_only": True, "owned_tls_controls_passed": len(results)}))


if __name__ == "__main__":
    main()
