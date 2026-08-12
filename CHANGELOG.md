# Changelog

All notable changes to OSEye are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.1] — 2026-08-12

First experimental release.

### Added
- Agent Go with 9 collectors (eBPF, auditd, fanotify, inotify, procfs, netlink, journald, udev, syslog)
- gRPC/mTLS transport with Ed25519 batch signing and BLAKE3 hash chain
- Offline SQLite buffer with full-jitter backoff
- CLI `oseye-config` for secure agent configuration management
- Server Python (FastAPI) with normalizer, rule engine (35+ YAML rules), ML engine (River HalfSpaceTrees)
- Threat intelligence engine (AbuseIPDB, VirusTotal, MISP) with circuit breaker
- Correlation engine with auto-close incidents
- Decision Engine (8 decision types, risk matrix, immutable BLAKE3 journal)
- Response Engine (BLOCK_IP, QUARANTINE_FILE, KILL_PROCESS) with rollback
- Forensics module (case management, custody log, PDF/MISP/TheHive export)
- Plugin SDK Python (AnalyzerPlugin, ExporterPlugin, CollectorPlugin) with Ed25519 signature
- 6 surveillance profiles (workstation, server, investigation, minimal, compliance, stealth)
- Dashboard React/TypeScript with analyst + admin RBAC views
- Auto-enrollment for agents (first boot PKI provisioning)
- Resource watchdog (CPU/RAM throttling)
- .deb/.rpm packaging with systemd integration
- Docker image (multi-arch linux/amd64, linux/arm64)
- CI pipeline (lint, test, build)
- Release workflow with SHA256 checksums, GPG signing, cosign

### Security
- Config validation: strict port/path/UUID/bounds checks, critical path rejection
- Atomic config writes with file locking (flock)
- Secrets masking in CLI output
- Newline injection prevention in env file
- Permissions 0600 on all config files
- -trimpath for reproducible builds
- Digest-pinned Docker base images
