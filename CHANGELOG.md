# Changelog

All notable changes to MacNoise will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries from this point on are generated automatically by
> [release-please](https://github.com/googleapis/release-please) from
> Conventional Commits PR titles - see CONTRIBUTING.md#versioning for the
> required format. You no longer need to hand-edit this file.

## [0.2.1](https://github.com/0xv1n/macnoise/compare/v0.2.0...v0.2.1) (2026-08-01)


### Bug Fixes

* give proc_gatekeeper's 4 events distinct labels ([#15](https://github.com/0xv1n/macnoise/issues/15)) ([83944e5](https://github.com/0xv1n/macnoise/commit/83944e5e71ad5abc76daa48f47ebe940030a3d33))
* redact hidden-answer osascript output and cap AMOS dialog timeout ([#13](https://github.com/0xv1n/macnoise/issues/13)) ([e1be04b](https://github.com/0xv1n/macnoise/commit/e1be04ba762557413990864ab07ac516abd2a6c4))
* restore prior state correctly in file_modify and plist_modify cleanup ([#11](https://github.com/0xv1n/macnoise/issues/11)) ([d53203c](https://github.com/0xv1n/macnoise/commit/d53203c581a3bc04eac04466f8adf70f821e1b69))
* thread es_process's chain_depth through argv instead of nested string quoting ([#16](https://github.com/0xv1n/macnoise/issues/16)) ([2335090](https://github.com/0xv1n/macnoise/commit/23350904055af92f8a0e921ba6872081e9e5bcaf))

## [0.2.0](https://github.com/0xv1n/macnoise/compare/v0.1.0...v0.2.0) (2026-07-31)


### Features

* automate releases with release-please and Conventional Commits ([#7](https://github.com/0xv1n/macnoise/issues/7)) ([87a00c4](https://github.com/0xv1n/macnoise/commit/87a00c4fc7d7c6728394e2c2b0dc1c4688eb5925))


### Bug Fixes

* correct release-please tag component config for existing repo ([#8](https://github.com/0xv1n/macnoise/issues/8)) ([7b813f7](https://github.com/0xv1n/macnoise/commit/7b813f79fafb48a6a4930dddd6c5b07a84c601df))
* don't overwrite crontab when listing it fails ([#6](https://github.com/0xv1n/macnoise/issues/6)) ([7f1335f](https://github.com/0xv1n/macnoise/commit/7f1335f6b1c75e75e5cf033b14061ef8e0019887))

## [Unreleased]

### Fixed

- Module `Cleanup()` now runs when a run is interrupted, so Ctrl-C no longer
  leaves persistence artifacts on the host.
- An interrupted scenario stops at the step it reached and still writes its
  audit record.
- `svc_cron` no longer overwrites the user's crontab when `crontab -l` fails
  for a reason other than "no crontab exists" (e.g. access denied); it now
  aborts instead. `Cleanup()` also reports an error instead of silently
  succeeding when it can't verify the installed entry was removed.

### Changed

- `make test` and `make coverage` now include `./cmd/...` and `./modules/...`.

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
