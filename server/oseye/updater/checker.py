"""Check GitHub Releases for a newer oseye-server binary."""

from __future__ import annotations

import logging
import platform
import sys
import re
from dataclasses import dataclass

import httpx
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

_logger = logging.getLogger(__name__)

_GITHUB_API_LATEST = "https://api.github.com/repos/{repo}/releases/latest"
_GITHUB_API_ALL = "https://api.github.com/repos/{repo}/releases"
_GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

_PLATFORM_MAP: dict[tuple[str, str], str] = {
    ("linux", "x86_64"): "linux-amd64",
    ("linux", "aarch64"): "linux-arm64",
    ("darwin", "x86_64"): "darwin-amd64",
    ("darwin", "arm64"): "darwin-arm64",
}


@dataclass
class UpdateInfo:
    available: bool
    current: str
    latest: str
    download_url: str | None = None
    sha256_url: str | None = None
    release_notes: str | None = None
    release_url: str | None = None


def current_version() -> str:
    try:
        return _pkg_version("oseye-server")
    except PackageNotFoundError:
        return "dev"


def asset_platform() -> str | None:
    return _PLATFORM_MAP.get((sys.platform, platform.machine()))


_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


async def _fetch_release(repo: str, include_pre: bool) -> dict | None:
    if not _REPO_RE.match(repo):
        raise ValueError(f"Invalid update_github_repo format: {repo!r}  (expected 'owner/repo')")
    url = _GITHUB_API_ALL.format(repo=repo) if include_pre else _GITHUB_API_LATEST.format(repo=repo)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=_GITHUB_HEADERS)
            resp.raise_for_status()
            data = resp.json()
            if include_pre:
                return next((r for r in data if not r.get("draft")), None)
            return data  # type: ignore[return-value]
    except Exception as exc:
        _logger.debug("update_check_failed reason=%s", exc)
        return None


async def check_update(repo: str, include_pre: bool = False) -> UpdateInfo:
    from packaging.version import InvalidVersion, Version

    current = current_version()
    if current == "dev":
        return UpdateInfo(available=False, current=current, latest="unknown")

    release = await _fetch_release(repo, include_pre)
    if not release:
        return UpdateInfo(available=False, current=current, latest="unknown")

    tag = release.get("tag_name", "").lstrip("v")
    try:
        available = Version(tag) > Version(current)
    except InvalidVersion:
        return UpdateInfo(available=False, current=current, latest=tag)

    download_url = sha256_url = None
    if available:
        plat = asset_platform()
        if plat:
            binary_name = f"oseye-server-{plat}"
            for asset in release.get("assets", []):
                name = asset.get("name", "")
                if name == binary_name:
                    download_url = asset.get("browser_download_url")
                elif name == f"{binary_name}.sha256":
                    sha256_url = asset.get("browser_download_url")

    return UpdateInfo(
        available=available,
        current=current,
        latest=tag,
        download_url=download_url,
        sha256_url=sha256_url,
        release_notes=release.get("body"),
        release_url=release.get("html_url"),
    )
