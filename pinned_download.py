"""Bounded HTTPS downloads for reviewed public archives; no account credentials."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024


def require_https_release_url(url: str) -> None:
    try:
        target = urllib.parse.urlsplit(url)
        valid = target.scheme == "https" and bool(target.hostname) and target.username is None and target.password is None
    except ValueError:
        valid = False
    if not valid:
        raise RuntimeError("Release download must retain HTTPS without user credentials")


class HTTPSReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require_https_release_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_release(root: Path, archive: Path, url: str, expected: str, *, api: bool = False, max_bytes: int | None = None) -> None:
    # A fresh opener uses no ambient global auth/cookie handler. The public
    # asset needs no GitHub, Codex or model credential. Keep configured proxies.
    require_https_release_url(url)
    limit = MAX_ARCHIVE_BYTES if max_bytes is None else max_bytes
    if type(limit) is not int or not 1 <= limit <= MAX_ARCHIVE_BYTES:
        raise RuntimeError("Invalid pinned archive download limit")
    if archive.is_symlink():
        raise RuntimeError("Pinned archive cache must not be symlinked")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if sys.version_info >= (3, 13):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN | ssl.VERIFY_X509_STRICT
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    context.keylog_filename = None
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), HTTPSReleaseRedirect())
    headers = {"User-Agent": "claude-codex-http-bridge-installer"}
    if api:
        headers["Accept"] = "application/octet-stream"
    request = urllib.request.Request(url, headers=headers)
    temporary = None
    try:
        with opener.open(request, timeout=60) as response:
            digest, total = hashlib.sha256(), 0
            with tempfile.NamedTemporaryFile(dir=root, prefix="download-", delete=False) as handle:
                temporary = Path(handle.name)
                while block := response.read(64 * 1024):
                    total += len(block)
                    if total > limit:
                        raise RuntimeError("Pinned release archive exceeds its download limit")
                    digest.update(block)
                    handle.write(block)
        if digest.hexdigest() != expected:
            raise RuntimeError("Pinned archive SHA-256 does not match its reviewed digest")
        os.replace(temporary, archive)
        archive.chmod(0o600)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def download_with_api_fallback(root: Path, archive: Path, primary: str, alternate: str | None,
                               expected: str, *, max_bytes: int | None = None) -> None:
    """Allow one official alternate after a gateway refusal or typed timeout."""
    if alternate is not None and not re.fullmatch(
            r"https://api\.github\.com/repos/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/releases/assets/[1-9][0-9]{0,19}", alternate):
        raise RuntimeError("Alternate release download must use GitHub's official asset API")
    try:
        fallback = None
        try:
            download_release(root, archive, primary, expected, max_bytes=max_bytes)
        except urllib.error.HTTPError as error:
            if error.code not in (502, 503, 504) or alternate is None:
                raise
            error.close()
            fallback = f"returned HTTP {error.code}"
        except urllib.error.URLError as error:
            # urllib wraps connection timeouts but a response-body read can
            # raise TimeoutError directly. Never classify by an error string.
            if not isinstance(error.reason, TimeoutError) or alternate is None:
                raise
            fallback = "timed out"
        except TimeoutError:
            if alternate is None:
                raise
            fallback = "timed out"
        if fallback is not None:
            print(f"Pinned release download {fallback}; trying GitHub's official asset API.", file=sys.stderr)
            download_release(root, archive, alternate, expected, api=True, max_bytes=max_bytes)
    except urllib.error.HTTPError as error:
        error.close()
        raise RuntimeError(f"Pinned release download failed (HTTP {error.code})") from None
    except (urllib.error.URLError, ssl.SSLError):
        raise RuntimeError("Pinned release download failed (TLS or transport error)") from None
    except TimeoutError:
        raise RuntimeError("Pinned release download failed (network timeout)") from None
