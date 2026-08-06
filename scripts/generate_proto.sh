#!/usr/bin/env bash
# Generate Go and Python code from proto/event.proto
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROTO_DIR="$REPO_ROOT/proto"
GO_OUT="$REPO_ROOT/agent/gen"
PY_OUT="$REPO_ROOT/server/gen"

echo "==> Generating protobuf code from $PROTO_DIR"

mkdir -p "$GO_OUT" "$PY_OUT"

# Go: standard protobuf + gRPC
protoc \
  --proto_path="$PROTO_DIR" \
  --go_out="$GO_OUT" \
  --go_opt=paths=source_relative \
  --go-grpc_out="$GO_OUT" \
  --go-grpc_opt=paths=source_relative \
  "$PROTO_DIR/event.proto"

# Python: standard protobuf + gRPC
PYTHON="${VENV_PYTHON:-python3}"
"$PYTHON" -m grpc_tools.protoc \
  -I"$PROTO_DIR" \
  --python_out="$PY_OUT" \
  --grpc_python_out="$PY_OUT" \
  "$PROTO_DIR/event.proto"

# Fix relative imports in generated Python gRPC file
if [ -f "$PY_OUT/event_pb2_grpc.py" ]; then
  sed -i 's/^import event_pb2/from . import event_pb2/' "$PY_OUT/event_pb2_grpc.py"
fi

# Create __init__.py so gen/ is importable as a package
touch "$PY_OUT/__init__.py"

echo "==> Done."
echo "    Go  : $GO_OUT"
echo "    Python: $PY_OUT"
