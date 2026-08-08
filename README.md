<div style="text-align: center;">
  <img src="macnoise.png" alt="Description of image" style="max-width: 100%; height: auto; display: block; margin: 0 auto;">
</div>

---

[![CI](https://github.com/0xv1n/macnoise/actions/workflows/ci.yaml/badge.svg)](https://github.com/0xv1n/macnoise/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/0xv1n/macnoise)](https://github.com/0xv1n/macnoise/releases/latest)

# MacNoise

MacNoise generates real macOS telemetry: network connections, file writes, process spawns, plist mutations, TCC probes, and more. Point it at a machine running your EDR, SIEM, or firewall stack and see what actually fires - not what the vendor datasheet claims will fire.

For background on the motivation and design, see the [release blog post](https://0xv1n.github.io/posts/macnoise/).

## Quick Start

```bash
# Build (add build-amd64 / build-arm64 to cross-compile for Darwin, or release for both)
make build

# List available modules
./macnoise list

# Run a single module
./macnoise run net_connect --param target=127.0.0.1 --param port=8080

# Preview without executing
./macnoise run svc_launch_agent --dry-run

# Run all network modules
./macnoise run --category network

# Run a scenario
./macnoise scenario configs/scenarios/edr_validation.yaml

# Emit structured JSONL output
./macnoise run --category file --format jsonl --output /tmp/events.jsonl
```

## Telemetry Categories

| Category | Description | Modules |
|----------|-------------|---------|
| `network` | Outbound connections, DNS, beaconing, listeners, reverse shells, exfiltration | net_connect, net_listen, net_beacon, net_revshell, net_dns, net_exfil |
| `process` | Process spawning, signal delivery, dylib injection, discovery, Gatekeeper bypass, osascript | proc_spawn, proc_signal, proc_inject, proc_discovery, proc_gatekeeper, proc_osascript |
| `file` | File creation, modification, browser credential reads, archiving, hiding | file_create, file_modify, file_browser_creds, file_archive, file_hide |
| `tcc` | TCC permission probes (FDA, Contacts, Keychain) | tcc_fda, tcc_contacts, tcc_keychain |
| `endpoint_security` | ES framework event triggers | es_file, es_process |
| `service` | LaunchAgent/Daemon persistence, cron, shell profile | svc_launch_agent, svc_launch_daemon, svc_cron, svc_shell_profile |
| `plist` | Plist creation and modification | plist_create, plist_modify |
| `xpc` | XPC service enumeration | xpc_enumerate |

## Commands

```
macnoise run <module> [--param key=val ...]   Run a specific module
macnoise run --category <cat>                 Run all modules in a category
macnoise run --all                            Run all modules
macnoise list [--category <cat>]              List modules
macnoise info <module>                        Show module details, params, MITRE
macnoise scenario <file.yaml>                 Run a YAML scenario
macnoise categories                           List categories with counts
macnoise version                              Print version
```

### Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `human` | Output format: `human` or `jsonl` |
| `--output` | (none) | Write output to file (in addition to stdout) |
| `--verbose` | false | Verbose output including cleanup errors |
| `--dry-run` | false | Preview actions without executing |
| `--timeout` | `30` | Per-module timeout in seconds |
| `--audit-log` | (none) | Write OCSF 1.7.0 audit records to a JSONL file |
| `--config` | (none) | Load defaults from a YAML config file |

## Audit Logging

MacNoise writes two separate streams. Telemetry events - what your EDR/SIEM actually sees - go to stdout or `--output`. A second, optional stream records what MacNoise itself did: which modules ran, prereq/cleanup outcomes, and MITRE mappings, in [OCSF 1.7.0](https://schema.ocsf.io/) JSONL.

```bash
./macnoise scenario configs/scenarios/amos_atomic_stealer.yaml --audit-log /tmp/audit.jsonl
```

The audit log opens in append mode, so records from multiple runs pile up in one file for batch analysis. If you're adding a module and want to know how a new event type gets classified into OCSF, see [CONTRIBUTING.md](CONTRIBUTING.md#audit-logging-ocsf).

## Module Reference

Module documentation lives alongside each category:

| Category | README |
|----------|--------|
| `network` | [modules/network/README.md](modules/network/README.md) |
| `process` | [modules/process/README.md](modules/process/README.md) |
| `file` | [modules/file/README.md](modules/file/README.md) |
| `tcc` | [modules/tcc/README.md](modules/tcc/README.md) |
| `endpoint_security` | [modules/endpoint_security/README.md](modules/endpoint_security/README.md) |
| `service` | [modules/service/README.md](modules/service/README.md) |
| `plist` | [modules/plist/README.md](modules/plist/README.md) |
| `xpc` | [modules/xpc/README.md](modules/xpc/README.md) |

## Scenarios

Scenarios chain modules into ordered sequences - a single YAML file that replays a multi-stage intrusion pattern against your detections.

| File | Description |
|------|-------------|
| `network_only.yaml` | All network modules |
| `edr_validation.yaml` | Comprehensive EDR detection coverage |
| `full_sweep.yaml` | All categories |
| `lazarus_group.yaml` | Lazarus Group: dylib injection, service discovery, reverse shell, plist persistence |
| `amos_atomic_stealer.yaml` | AMOS / Atomic Stealer: MaaS infostealer, Gatekeeper bypass, keychain dump, ZIP exfil, backdoor persistence |

The two APT scenarios follow real documented intrusion sequences, technique by technique - each YAML file cites the actual threat intel it's built from and annotates every step with the MITRE technique it exercises, so start there for the full breakdown rather than a retelling here.

**Dry-run first:**
```bash
./macnoise scenario configs/scenarios/<scenario>.yaml --dry-run
```

**Cross-reference with your SIEM/EDR:** each step comment names the technique it should trigger. No matching alert after a real run is a gap in your coverage.

**Writing your own:**
```yaml
name: My Custom Scenario
steps:
  - module: net_connect
    params:
      target: "192.168.1.1"
      port: "443"
  - category: file
    params:
      base_dir: "/tmp/test"
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for adding new modules, code style, and the full PR process.

Releases are automated - [release-please](https://github.com/googleapis/release-please) cuts a new version straight from your [Conventional Commit](https://www.conventionalcommits.org/) PR title, so `feat: add net_tls module` or `fix: correct beacon jitter` is both your PR title and your changelog entry.

## Disclaimer

MacNoise is intended for **authorized** security testing, EDR validation, and detection engineering on systems you own or have explicit written permission to test. The authors assume no liability for misuse.

## AI Code Policy

AI Code contributions are fine, but please keep in mind that code review is currently going to be a human-led process which means there is only so much code we can review. Please limit PRs to a specific fix, or new telemetry module. PRs with extensive changes are likely going to be closed.
