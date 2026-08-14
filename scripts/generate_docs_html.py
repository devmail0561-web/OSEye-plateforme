#!/usr/bin/env python3
"""Generate OSEye internal HTML docs from Markdown using pandoc.

Usage: python3 scripts/generate_docs_html.py
Run from repo root.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "docs" / "internal"

# The exact CSS extracted from the original working HTML (commit 4f71c73).
# Contains: pandoc syntax-highlight CSS + custom OSEye dark sidebar CSS.
# Does NOT include pandoc's default body layout CSS (max-width, padding, etc.)
# which would break the flex sidebar layout.
_ORIGINAL_CSS_PATH = DOCS_DIR / "_template_css.txt"

# Docs to generate: (md_path, html_path, title, version_badge)
DOCS = [
    (
        DOCS_DIR / "ARCHITECTURE.md",
        DOCS_DIR / "ARCHITECTURE.html",
        "OSEye — Software Architecture Document",
        "v1.2",
    ),
    (
        DOCS_DIR / "PROGRESS.md",
        DOCS_DIR / "PROGRESS.html",
        "OSEye — Suivi de progression",
        "v0.1.0-α1",
    ),
    (
        DOCS_DIR / "DEVELOPMENT_PLAN.md",
        DOCS_DIR / "DEVELOPMENT_PLAN.html",
        "OSEye — Plan de développement",
        "v0.1.0-α1",
    ),
    (
        DOCS_DIR / "DEVELOPMENT_PLAN_PHASE2.md",
        DOCS_DIR / "DEVELOPMENT_PLAN_PHASE2.html",
        "OSEye — Plan de développement Phase 2",
        "v0.1.0-α1",
    ),
    (
        DOCS_DIR / "PLAN_ACTION.md",
        DOCS_DIR / "PLAN_ACTION.html",
        "OSEye — Plan d'action",
        "v0.1.0-α1",
    ),
    (
        DOCS_DIR / "CONDUCT.md",
        DOCS_DIR / "CONDUCT.html",
        "OSEye — Code of Conduct",
        "v0.1.0-α1",
    ),
    (
        DOCS_DIR / "CONTRIBUTING.md",
        DOCS_DIR / "CONTRIBUTING.html",
        "OSEye — Contributing Guide",
        "v0.1.0-α1",
    ),
]


def _run_pandoc_fragment(md_path: Path) -> str:
    """Run pandoc without --standalone to get the body fragment (no CSS)."""
    result = subprocess.run(
        [
            "pandoc",
            "--highlight-style=pygments",
            "-f", "markdown",
            "-t", "html5",
            str(md_path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _run_pandoc_toc(md_path: Path) -> str:
    """Run pandoc with --toc --standalone and extract only the <nav id='TOC'> block."""
    result = subprocess.run(
        [
            "pandoc",
            "--standalone",
            "--toc",
            "--toc-depth=3",
            "-f", "markdown",
            "-t", "html5",
            str(md_path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    html = result.stdout
    # Extract <nav id="TOC">...</nav>
    m = re.search(r'<nav id="TOC"[^>]*>(.*?)</nav>', html, re.DOTALL)
    if m:
        return m.group(0)
    # Fallback: extract <ul> items from the first nav or toc block
    m = re.search(r'<ul>\s*<li>.*?</ul>', html, re.DOTALL)
    return m.group(0) if m else ""


def generate_html(
    md_path: Path,
    html_path: Path,
    title: str,
    version: str,
    css: str,
) -> None:
    """Build complete HTML from MD using pandoc fragments + original CSS template."""
    body_fragment = _run_pandoc_fragment(md_path)
    toc_nav = _run_pandoc_toc(md_path)

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
{css}
</head>
<body>

<div id="sidebar">
  <div class="sidebar-brand">
    <span class="logo-text">OSEye</span>
    <span class="logo-badge">{version}</span>
  </div>
  {toc_nav}
</div>

<div id="main">
  <article id="article">
{body_fragment}  </article>
</div>

</body>
</html>
"""
    html_path.write_text(html, encoding="utf-8")
    print(f"  OK  {html_path.name}  ({len(html_path.read_bytes()) // 1024} KB)")


def main() -> int:
    # Load the original CSS template
    if not _ORIGINAL_CSS_PATH.exists():
        print(
            f"ERROR: CSS template not found at {_ORIGINAL_CSS_PATH}\n"
            "Run: git show 4f71c73:docs/internal/ARCHITECTURE.html | "
            "python3 -c \"import sys; lines=sys.stdin.readlines(); "
            "print(''.join(lines[6:427]))\" > docs/internal/_template_css.txt",
            file=sys.stderr,
        )
        return 1

    css = _ORIGINAL_CSS_PATH.read_text(encoding="utf-8").strip()

    print("Generating OSEye docs HTML...")
    errors = 0
    for md_path, html_path, title, version in DOCS:
        if not md_path.exists():
            print(f"  SKIP {md_path.name} (not found)")
            continue
        try:
            generate_html(md_path, html_path, title, version, css)
        except subprocess.CalledProcessError as exc:
            print(f"  FAIL {md_path.name}: pandoc error: {exc.stderr[:200]}", file=sys.stderr)
            errors += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  FAIL {md_path.name}: {exc}", file=sys.stderr)
            errors += 1

    if errors == 0:
        print(f"\nDone — {len(DOCS)} files generated.")
    else:
        print(f"\nDone with {errors} error(s).")
    return errors


if __name__ == "__main__":
    sys.exit(main())
