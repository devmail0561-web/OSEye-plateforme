#!/usr/bin/env bash
# Test proto compilation — verify generated files are up-to-date
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Testing proto compilation..."

# Check protoc is available
if ! command -v protoc &>/dev/null; then
  echo "ERROR: protoc not found in PATH"
  exit 1
fi

# Check grpcio-tools is available in venv
if [ -f ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
else
  PYTHON="${VENV_PYTHON:-python3}"
fi

if ! "$PYTHON" -c "import grpc_tools.protoc" 2>/dev/null; then
  echo "ERROR: grpcio-tools not installed"
  echo "Run: pip install grpcio-tools"
  exit 1
fi

# Generate into temporary directories
TMP_GO=$(mktemp -d)
TMP_PY=$(mktemp -d)
trap "rm -rf $TMP_GO $TMP_PY" EXIT

echo "==> Generating into temp directories..."

# Go
protoc \
  --proto_path="proto" \
  --go_out="$TMP_GO" \
  --go_opt=paths=source_relative \
  --go-grpc_out="$TMP_GO" \
  --go-grpc_opt=paths=source_relative \
  proto/event.proto

# Python
"$PYTHON" -m grpc_tools.protoc \
  -I"proto" \
  --python_out="$TMP_PY" \
  --grpc_python_out="$TMP_PY" \
  proto/event.proto

echo "==> Comparing with committed files..."

# Compare Go files
if ! diff -q "$TMP_GO/event.pb.go" "agent/gen/event.pb.go" >/dev/null; then
  echo "ERROR: agent/gen/event.pb.go is out of date"
  echo "Run: ./scripts/generate_proto.sh"
  exit 1
fi

if ! diff -q "$TMP_GO/event_grpc.pb.go" "agent/gen/event_grpc.pb.go" >/dev/null; then
  echo "ERROR: agent/gen/event_grpc.pb.go is out of date"
  echo "Run: ./scripts/generate_proto.sh"
  exit 1
fi

# Compare Python files (ignore sed fix for relative imports)
if ! diff -q "$TMP_PY/event_pb2.py" "server/gen/event_pb2.py" >/dev/null; then
  echo "ERROR: server/gen/event_pb2.py is out of date"
  echo "Run: ./scripts/generate_proto.sh"
  exit 1
fi

# For gRPC file, ignore import line differences
if ! diff -I '^import event_pb2' -I '^from . import event_pb2' -q \
     "$TMP_PY/event_pb2_grpc.py" "server/gen/event_pb2_grpc.py" >/dev/null; then
  echo "ERROR: server/gen/event_pb2_grpc.py is out of date"
  echo "Run: ./scripts/generate_proto.sh"
  exit 1
fi

echo "==> All generated files are up-to-date ✓"
