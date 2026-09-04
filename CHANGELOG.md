# Changelog

All notable changes to MacNoise will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries from this point on are generated automatically by
> [release-please](https://github.com/googleapis/release-please) from
> Conventional Commits PR titles - see CONTRIBUTING.md#versioning for the
> required format. You no longer need to hand-edit this file.

## [0.6.0](https://github.com/0xv1n/macnoise/compare/v0.5.0...v0.6.0) (2026-09-04)


### Features

* add emitted event types to module catalog ([#55](https://github.com/0xv1n/macnoise/issues/55)) ([b10085a](https://github.com/0xv1n/macnoise/commit/b10085a4451c7f1e8347e70b24093bfbec70538e))
* emit machine-readable module catalog via list --format jsonl ([#54](https://github.com/0xv1n/macnoise/issues/54)) ([4e43bbd](https://github.com/0xv1n/macnoise/commit/4e43bbd6af80fdffb660787c2247c45a8330f222))
* extend run ID stamping to all artifact-producing modules ([#53](https://github.com/0xv1n/macnoise/issues/53)) ([b69944e](https://github.com/0xv1n/macnoise/commit/b69944eb4477727a89b642639def381cf65a4973))
* fold run ID into module artifacts for host telemetry correlation ([#52](https://github.com/0xv1n/macnoise/issues/52)) ([ef76f21](https://github.com/0xv1n/macnoise/commit/ef76f21b4ee487e6eba4183d59eb029bef3ca033))
* lift run ID to runner and expose via module context ([#51](https://github.com/0xv1n/macnoise/issues/51)) ([ebcab38](https://github.com/0xv1n/macnoise/commit/ebcab389e86df90f1ea6d4dc7035e7826949bdad))


### Bug Fixes

* register evasion module and clean up plist parent directory ([#49](https://github.com/0xv1n/macnoise/issues/49)) ([26fa322](https://github.com/0xv1n/macnoise/commit/26fa322ce9ec80006d618c1343371aa2d1bbf885))

## [0.5.0](https://github.com/0xv1n/macnoise/compare/v0.4.0...v0.5.0) (2026-08-28)


### Features

* add clickfix scenario for malicious copy-paste delivery ([#42](https://github.com/0xv1n/macnoise/issues/42)) ([5c169cd](https://github.com/0xv1n/macnoise/commit/5c169cd24ec74bdee404235137673fdd92e3e53f))
* add evade_log_clear module for defense evasion telemetry ([#47](https://github.com/0xv1n/macnoise/issues/47)) ([40cbdaa](https://github.com/0xv1n/macnoise/commit/40cbdaabf3251ac0705761b22af48742763a09e2))
* add net_dns_exfil for DNS subdomain exfiltration telemetry ([#46](https://github.com/0xv1n/macnoise/issues/46)) ([ecd65a4](https://github.com/0xv1n/macnoise/commit/ecd65a476e0151d13a4782b318a48bb70e0db76f))
* add net_tls module for TLS handshake telemetry ([#48](https://github.com/0xv1n/macnoise/issues/48)) ([2a95e06](https://github.com/0xv1n/macnoise/commit/2a95e0665bceea533dd64d584be059c8743ca057))
* add security software discovery to proc_discovery ([#45](https://github.com/0xv1n/macnoise/issues/45)) ([cfd2cf9](https://github.com/0xv1n/macnoise/commit/cfd2cf90b72af9e29958e87218e846553ba62815))
* extend es_file to cover ES open, setmode, and rename events ([#44](https://github.com/0xv1n/macnoise/issues/44)) ([d989926](https://github.com/0xv1n/macnoise/commit/d9899267647a5a4467cdf5ba067320d07c18e327))

## [0.4.0](https://github.com/0xv1n/macnoise/compare/v0.3.0...v0.4.0) (2026-08-11)


### ⚠ BREAKING CHANGES

* correct xpc module scope, parser, and MITRE mapping ([#32](https://github.com/0xv1n/macnoise/issues/32))

### Features

* add --no-cleanup and clear a batch of CLI and telemetry paper cuts ([#34](https://github.com/0xv1n/macnoise/issues/34)) ([939d5c0](https://github.com/0xv1n/macnoise/commit/939d5c093c5ee0001cb85a6c3cd26955e627b8ba))
* add cred_files to probe non-browser credential files ([#38](https://github.com/0xv1n/macnoise/issues/38)) ([3d418e7](https://github.com/0xv1n/macnoise/commit/3d418e77b702cb34ba585b17aca52b3611f527e3))
* add es_mount to emulate .dmg delivery ([#36](https://github.com/0xv1n/macnoise/issues/36)) ([41af1f4](https://github.com/0xv1n/macnoise/commit/41af1f450d849cf5a13b00e661b2cecbac53ae41))
* add event outcome to distinguish a refused action from a broken tool ([#35](https://github.com/0xv1n/macnoise/issues/35)) ([9320a5a](https://github.com/0xv1n/macnoise/commit/9320a5ac57c38e0a39821eef44ea9120964b9ce4))
* add file_keychain_copy to stage wholesale keychain copies ([#40](https://github.com/0xv1n/macnoise/issues/40)) ([9220b95](https://github.com/0xv1n/macnoise/commit/9220b95cb537c6de5eb35816c616373a5994256c))
* add svc_login_item for Login Items / BTM persistence ([#37](https://github.com/0xv1n/macnoise/issues/37)) ([c8545b9](https://github.com/0xv1n/macnoise/commit/c8545b9ee7b3df8abd17843528031a5988c6e1ca))
* add tcc_accessibility and tcc_screen_recording probes ([#39](https://github.com/0xv1n/macnoise/issues/39)) ([c1aeb39](https://github.com/0xv1n/macnoise/commit/c1aeb39ebf91b45c7e97c31b272121e4b7bf7f01))


### Bug Fixes

* correct xpc module scope, parser, and MITRE mapping ([#32](https://github.com/0xv1n/macnoise/issues/32)) ([6620f54](https://github.com/0xv1n/macnoise/commit/6620f54a5dd881b1c3f0cb8da3dc411817bee059))
* derive dry-run command from the executed launchctl argv ([#31](https://github.com/0xv1n/macnoise/issues/31)) ([1dd2a36](https://github.com/0xv1n/macnoise/commit/1dd2a363e8f444e0d5ead51357e902c8eaa06f0f))
* distinguish absent resources from TCC denials in probe modules ([#28](https://github.com/0xv1n/macnoise/issues/28)) ([b5cf791](https://github.com/0xv1n/macnoise/commit/b5cf7916fcd993dd9123a9a47d6139099a363381))
* target an injectable binary in proc_inject and report the real dyld outcome ([#33](https://github.com/0xv1n/macnoise/issues/33)) ([14e5697](https://github.com/0xv1n/macnoise/commit/14e5697342c5c46cb0db0fc664c7307e50f9fcd2))
* use launchctl bootstrap/bootout instead of legacy load/unload ([#30](https://github.com/0xv1n/macnoise/issues/30)) ([45b02cf](https://github.com/0xv1n/macnoise/commit/45b02cfaa546d095d07da2662b7350cffe9b74bc))

## [0.3.0](https://github.com/0xv1n/macnoise/compare/v0.2.1...v0.3.0) (2026-08-06)


### Features

* read browser credential files instead of stat-only probing ([#27](https://github.com/0xv1n/macnoise/issues/27)) ([377e7e0](https://github.com/0xv1n/macnoise/commit/377e7e0ecf0e23e490591a0ceeddf90c30efcddf))


### Bug Fixes

* correct net_dns MITRE mapping and add real T1518 coverage to proc_discovery ([#20](https://github.com/0xv1n/macnoise/issues/20)) ([2f64293](https://github.com/0xv1n/macnoise/commit/2f642932da19924ba80951f35a60117d598801e0))
* populate required OCSF file/process/device fields on audit records ([#23](https://github.com/0xv1n/macnoise/issues/23)) ([a08672e](https://github.com/0xv1n/macnoise/commit/a08672ea55dbdc40ed858445b6563d70c7740f98))
* rewrite OCSF classify.go to match real event types and correct activity IDs ([#22](https://github.com/0xv1n/macnoise/issues/22)) ([5c6360d](https://github.com/0xv1n/macnoise/commit/5c6360d8e53180553ba03e15ac778dffa31f6bbe))
* wire context cancellation into net_listen and net_revshell dials ([#24](https://github.com/0xv1n/macnoise/issues/24)) ([e6ddf4d](https://github.com/0xv1n/macnoise/commit/e6ddf4de91f4d99708e352bc01529977a7af7ff4))

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
