"""oseye-server update — download and install the latest binary release."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import sys
import tempfile


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _download(url: str, dest: str) -> None:
    import httpx

    with open(dest, "wb") as f:
        with httpx.Client(
            timeout=httpx.Timeout(connect=10.0, read=300.0, write=10.0, pool=10.0),
            follow_redirects=True,
        ) as client:
            with client.stream("GET", url) as resp:
                resp.raise_for_status()
                total = int(resp.headers.get("content-length", 0))
                done = 0
                for chunk in resp.iter_bytes(65536):
                    f.write(chunk)
                    done += len(chunk)
                    if total:
                        print(f"\r  {done * 100 // total}%", end="", flush=True)
    print()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _fetch_expected_sha256(url: str) -> str:
    import httpx

    resp = httpx.get(url, timeout=10.0, follow_redirects=True)
    resp.raise_for_status()
    return resp.text.split()[0].strip()


_SYSTEMCTL = "/usr/bin/systemctl"


def _restart() -> None:
    if os.path.isfile(_SYSTEMCTL):
        print("Restarting via systemd...")
        os.execv(_SYSTEMCTL, [_SYSTEMCTL, "restart", "oseye-server"])
    else:
        print("Restarting binary...")
        os.execv(sys.executable, sys.argv)


def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server update",
        description="Check for and install the latest oseye-server binary.",
    )
    parser.add_argument("--check-only", action="store_true",
                        help="Report available version without installing")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip confirmation prompt")
    parser.add_argument("--pre", action="store_true",
                        help="Include pre-release versions")
    args = parser.parse_args(argv)

    from oseye.config import Settings
    from oseye.updater.checker import check_update

    settings = Settings()
    include_pre = args.pre or settings.update_include_prerelease
    info = asyncio.run(check_update(settings.update_github_repo, include_pre))

    if not info.available:
        if info.latest == "unknown":
            print("Could not reach update server. Check your network connection.")
            if info.release_url:
                print(f"Manual download: {info.release_url}")
        else:
            print(f"Already up to date ({info.current}).")
        return

    print(f"New version available: {info.current} → {info.latest}")
    if info.release_url:
        print(f"Release page: {info.release_url}")

    if info.release_notes:
        lines = (info.release_notes or "").splitlines()
        preview = lines[:15]
        print("\nRelease notes:")
        for line in preview:
            print(f"  {line}")
        if len(lines) > 15:
            print(f"  ... ({len(lines) - 15} more lines at {info.release_url})")
        print()

    if args.check_only:
        return

    if not _is_frozen():
        print("Not running as a compiled binary.")
        print("Update via:  git pull && pip install -e server/")
        return

    if not info.download_url:
        print("No pre-built binary for this platform.")
        if info.release_url:
            print(f"Download manually from: {info.release_url}")
        return

    if not args.yes:
        try:
            answer = input(f"Install {info.latest}? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return
        if answer not in ("y", "yes"):
            print("Aborted.")
            return

    target = sys.executable

    with tempfile.NamedTemporaryFile(dir=tempfile.gettempdir(), delete=False, suffix=".new") as f:
        tmp_path = f.name

    try:
        print(f"Downloading {info.download_url}")
        _download(info.download_url, tmp_path)

        if not info.sha256_url:
            raise ValueError(
                "No SHA256 checksum published for this release — aborting. "
                f"Download manually from: {info.release_url}"
            )
        print("Verifying SHA256...")
        expected = _fetch_expected_sha256(info.sha256_url)
        actual = _sha256_file(tmp_path)
        if actual.lower() != expected.lower():
            raise ValueError(f"SHA256 mismatch: expected {expected}, got {actual}")
        print("  Integrity OK")

        os.chmod(tmp_path, 0o755)
        os.replace(tmp_path, target)
        print(f"Installed {info.latest} → {target}")

    except Exception as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        print(f"Update failed: {exc}", file=sys.stderr)
        sys.exit(1)

    _restart()
