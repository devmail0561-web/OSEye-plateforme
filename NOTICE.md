# OSEye — NOTICE

OSEye
Copyright 2026 M. Tendeng

This product is licensed under the Apache License, Version 2.0.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

---

## Author

**M. Tendeng** — original design, architecture, and implementation of the
OSEye EDR/SIEM platform, including:

- Go agent (eBPF collector pipeline, local rule engine, autonomous response,
  enrollment PKI, gRPC transport)
- Python server (FastAPI, Decision Engine, ML worker, Threat Intelligence,
  Forensics, Plugin SDK, gRPC ingest)
- React/TypeScript dashboard (analyst and admin UI)
- YAML rule set (35+ MITRE ATT&CK detections)
- Infrastructure (Docker, packaging, PKI tooling)

---

## Third-Party Components

This software incorporates third-party open-source components.
Each component retains its original license; see the relevant
`go.sum`, `package.json`, and `pyproject.toml` for the full list.

Notable dependencies and their licenses:

| Component | License |
|-----------|---------|
| cilium/ebpf | Apache 2.0 |
| zeebo/blake3 | CC0 1.0 |
| google.golang.org/grpc | Apache 2.0 |
| google.golang.org/protobuf | BSD 3-Clause |
| modernc.org/sqlite | BSD 3-Clause + ISC |
| FastAPI | MIT |
| SQLAlchemy | MIT |
| River (machine learning) | BSD 3-Clause |
| React | MIT |
| Lucide React | ISC |
| Vite | MIT |
