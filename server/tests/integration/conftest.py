"""conftest for integration tests — makes the repo root importable so that
server.gen (the generated protobuf stubs) can be imported by tests that
need to act as a real gRPC client."""

from __future__ import annotations

import os
import sys

# Add the project root (parent of server/) to sys.path so that
# `from server.gen import event_pb2` resolves correctly.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
