# Changelog

All notable changes to MacNoise will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Add your changes here under the appropriate subsection before opening a PR._

<!-- Subsections (remove any that are empty):
### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security
-->

---

## [0.1.0] - 2026-02-21

### Added

- **19 telemetry modules** across 8 categories:
  - `network`: `net_connect`, `net_listen`, `net_beacon`, `net_revshell`, `net_dns`
  - `process`: `proc_spawn`, `proc_signal`, `proc_inject`
  - `file`: `file_create`, `file_modify`
  - `tcc`: `tcc_fda`, `tcc_contacts`
  - `endpoint_security`: `es_file`, `es_process`
  - `service`: `svc_launch_agent`, `svc_launch_daemon`
  - `plist`: `plist_create`, `plist_modify`
  - `xpc`: `xpc_connect`
- Cobra CLI with `run`, `list`, `info`, `scenario`, `categories`, and `version` commands
- JSONL and human-readable output formats via `internal/output`
- Scenario runner — chain modules into ordered sequences via YAML
- Pre-built scenarios: `network_only`, `edr_validation`, `full_sweep`, `lazarus_group`,  `amos_atomic_stealer`
- OCSF 1.7.0-aligned audit log via `--audit-log <path>` (`internal/audit`)
- `--dry-run` flag across all modules and scenarios
- Cross-compiled release binaries for `darwin/amd64` and `darwin/arm64`
- CI pipeline (lint, unit tests, macOS integration tests, multi-arch build)

[Unreleased]: https://github.com/0xv1n/macnoise/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/0xv1n/macnoise/releases/tag/v0.1.0
