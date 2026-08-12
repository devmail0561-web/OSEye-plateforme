#!/usr/bin/env bash
set -euo pipefail

VERSION=$(cat "$(dirname "$0")/../VERSION")

echo "Syncing version: $VERSION"

# Python server (pyproject.toml)
PYPROJECT="$(dirname "$0")/../server/pyproject.toml"
if [ -f "$PYPROJECT" ]; then
  sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" "$PYPROJECT"
  echo "  updated $PYPROJECT"
fi

# UI (package.json)
PACKAGE_JSON="$(dirname "$0")/../ui/package.json"
if [ -f "$PACKAGE_JSON" ]; then
  sed -i "s/\"version\": \".*\"/\"version\": \"${VERSION}\"/" "$PACKAGE_JSON"
  echo "  updated $PACKAGE_JSON"
fi

# Site (package.json)
SITE_PKG="$(dirname "$0")/../site/package.json"
if [ -f "$SITE_PKG" ]; then
  sed -i "s/\"version\": \".*\"/\"version\": \"${VERSION}\"/" "$SITE_PKG"
  echo "  updated $SITE_PKG"
fi

echo "Done."
