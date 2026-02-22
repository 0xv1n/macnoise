<div style="text-align: center;">
  <img src="macnoise.png" alt="Description of image" style="max-width: 100%; height: auto; display: block; margin: 0 auto;">
</div>

---

[![CI](https://github.com/0xv1n/macnoise/actions/workflows/ci.yaml/badge.svg)](https://github.com/0xv1n/macnoise/actions/workflows/ci.yaml)

# MacNoise

MacNoise is an extensible and modular MacOS system telemetry generation framework. The purpose of this project is to provide system and security teams a means of validating and auditing visibility across tooling such as SIEM, EDR, and Firewalls by generating **real** telemetry in a highly controlled and repeatable way.

## Quick Start

```bash
# Build
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
| `file` | File creation, modification, browser credential probing, archiving, hiding | file_create, file_modify, file_browser_creds, file_archive, file_hide |
| `tcc` | TCC permission probes (FDA, Contacts, Keychain) | tcc_fda, tcc_contacts, tcc_keychain |
| `endpoint_security` | ES framework event triggers | es_file, es_process |
| `service` | LaunchAgent/Daemon persistence, cron, shell profile | svc_launch_agent, svc_launch_daemon, svc_cron, svc_shell_profile |
| `plist` | Plist creation and modification | plist_create, plist_modify |
| `xpc` | XPC service enumeration | xpc_connect |

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
| `--output` | — | Write output to file (in addition to stdout) |
| `--verbose` | false | Verbose output including cleanup errors |
| `--dry-run` | false | Preview actions without executing |
| `--timeout` | `30` | Per-module timeout in seconds |
| `--audit-log` | — | Write OCSF 1.7.0 audit records to a JSONL file |
| `--config` | — | Load defaults from a YAML config file |

## Audit Logging

MacNoise produces two distinct output streams:

- **Telemetry events** — the `TelemetryEvent` records written to stdout (or a file via `--output`) by every module. These are what your EDR, SIEM, or firewall sees.
- **Audit records** — a separate, structured log of what MacNoise itself did: which modules ran, prereq outcomes, timing, events emitted, cleanup results, and MITRE technique mappings.

Audit records are written in [OCSF 1.7.0](https://schema.ocsf.io/) (Open Cybersecurity Schema Framework) JSONL format. Each record is a valid OCSF class — HTTP activity maps to class 4002, DNS to 4003, network to 4001, file system to 1001, process to 1007, scheduled job to 1006 — with macnoise-specific fields placed in the `unmapped` object so the record remains schema-compliant.

Enable audit logging with `--audit-log`:

```bash
# Audit a single module run
./macnoise run net_connect --audit-log /tmp/audit.jsonl

# Audit a full scenario
./macnoise scenario configs/scenarios/amos_atomic_stealer.yaml \
  --audit-log /tmp/amos_audit.jsonl --format jsonl

# Audit log path can also be set per-scenario in the YAML (audit_log: /tmp/audit.jsonl)
# or as a default in a config file passed via --config
```

Each OCSF record contains:

| Field | Description |
|-------|-------------|
| `class_uid` / `class_name` | OCSF class (e.g. `4001 Network Activity`) |
| `activity_id` / `activity_name` | OCSF activity (e.g. `Connect`, `Listen`, `Create`) |
| `severity_id` / `status_id` | Reflects module step success or failure |
| `time` | Epoch milliseconds |
| `metadata.correlation_uid` | Shared run ID linking all records from one execution |
| `actor.process` | PID, executable, and username of the macnoise process |
| `attacks[]` | MITRE ATT&CK techniques from the module's `Info()` |
| `unmapped` | Module name, category, params, and lifecycle details |

The audit log is opened in append mode, so records from multiple runs accumulate in one file for batch analysis. Lifecycle records (prereq check, dry-run, cleanup) are written automatically by the runner — individual modules require no changes.

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

## MITRE ATT&CK Coverage

| Technique | Name | Modules |
|-----------|------|---------|
| T1041 | Exfiltration Over C2 Channel | net_exfil |
| T1053.003 | Scheduled Task/Job: Cron | svc_cron |
| T1059.002 | AppleScript | proc_osascript |
| T1059.004 | Unix Shell | net_revshell, proc_spawn, es_process |
| T1059.007 | JavaScript for Automation (JXA) | proc_osascript |
| T1071.001 | Web Protocols | net_connect, net_beacon |
| T1071.004 | DNS | net_dns |
| T1016 | System Network Configuration Discovery | proc_discovery |
| T1033 | System Owner/User Discovery | proc_discovery |
| T1082 | System Information Discovery | proc_discovery |
| T1106 | Native API | proc_signal |
| T1518 | Software Discovery | proc_discovery |
| T1543.001 | Launch Agent | svc_launch_agent |
| T1543.004 | Launch Daemon | svc_launch_daemon |
| T1546.004 | Unix Shell Configuration Modification | svc_shell_profile |
| T1553.001 | Gatekeeper Bypass | proc_gatekeeper |
| T1555 | Credentials from Password Stores | tcc_fda |
| T1555.001 | Keychain | tcc_keychain |
| T1555.003 | Credentials from Web Browsers | file_browser_creds |
| T1560.001 | Archive via Utility | file_archive |
| T1564.001 | Hidden Files and Directories | file_hide |
| T1574.006 | Dylib Injection | proc_inject |
| T1636.003 | Contact List | tcc_contacts |

## Scenarios

Scenarios chain modules into ordered sequences that emulate realistic attacker behavior. Each step runs a module or an entire category, optionally with params, making it straightforward to replay multi-stage intrusion patterns against your detections.

Pre-built scenarios are in `configs/scenarios/` to provide users with an example of the framework's capabilities:

| File | Description |
|------|-------------|
| `network_only.yaml` | All network modules |
| `edr_validation.yaml` | Comprehensive EDR detection coverage |
| `full_sweep.yaml` | All categories |
| `lazarus_group.yaml` | Lazarus Group — dylib injection, service discovery, reverse shell, plist persistence |
| `amos_atomic_stealer.yaml` | AMOS / Atomic Stealer (2023–2026) — MaaS infostealer, Gatekeeper bypass, keychain dump, ZIP exfil, backdoor persistence |

### APT Scenarios

The APT emulation scenarios follow documented intrusion sequences attributed to real threat groups, mapped to MITRE ATT&CK. Each step is annotated with the technique it exercises so you can correlate generated telemetry directly against expected alerts.

#### **Lazarus Group** (`lazarus_group.yaml`) 

Models a DPRK-style implant deployment: dropper execution → dylib injection into a legitimate process → XPC service enumeration → DNS C2 → reverse shell attempt → payload staging → plist persistence → persistent beaconing.

#### **AMOS / Atomic macOS Stealer** (`amos_atomic_stealer.yaml`)

A comprehensive scenario in this collection: 10 phases, 17 unique MacNoise modules, covering the full 2025 variant kill chain. Unlike the APT scenarios, AMOS is financially motivated crimeware (MaaS, ~$3,000/month on Telegram) with an aggressive, fast-moving collection profile.

| Phase | Description |
|-------|-------------|
| 1. Gatekeeper bypass | `xattr`/`chmod` strips the quarantine flag |
| 2. Defense evasion | osascript hides Terminal; fake "Auto-Updates System" password prompt (T1056.002) |
| 3. Credential access | `dscl` validation; keychain unlock and copy; Chromium, Firefox, and Safari credential sweeps |
| 4. Discovery | System profiling; XPC service enumeration; TCC Full Disk Access probe |
| 5. Collection | Desktop/Downloads/Documents file sweeps (WALLET/KEYS/TXT ≤ 51 KB); Notes; Telegram `tdata`; 7 crypto wallets (Exodus, Electrum, Ledger Live, and more) |
| 6. Staging | Local data staging; Ledger Live binary replacement (`proc_inject`, T1554) |
| 7. Exfiltration | ZIP archive; DNS resolution; HTTP POST |
| 8. Cleanup | Staging artifact removal |
| 9. Persistence | `.helper` backdoor download; `~/.agent` wrapper; `com.finder.helper` LaunchDaemon plist; LaunchAgent load |
| 10. C2 establishment | Bot ID registration; VM/sandbox detection; nested `es_process` chain; 60-second C2 poll loop |

*Sourced from SentinelOne, Picus Security, SpyCloud, Moonlock, Kandji, and Microsoft Defender research.*

### Validating Scenarios

**Dry-run first** — preview the full sequence without executing anything:
```bash
./macnoise scenario configs/scenarios/<scenario>.yaml --dry-run
```

**Structured output for automated correlation** — emit JSONL so every event carries module name, params, timestamps, and outcome:
```bash
./macnoise scenario configs/scenarios/<scenario>.yaml --format jsonl --output /tmp/<scenario>.jsonl
```

**Check individual module behavior before running a scenario** — inspect params and MITRE mappings:
```bash
./macnoise info proc_inject
```

**Cross-reference with your SIEM/EDR** — each step comment in the scenario YAML includes the expected MITRE technique. Use those to search for corresponding alerts after the run. If an alert is missing, the module that maps to that technique is a gap in your coverage.

### Writing Custom Scenarios

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

## Building

```bash
make build          # host OS
make build-amd64    # darwin/amd64
make build-arm64    # darwin/arm64
make release        # both Darwin architectures
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add new modules, code style expectations, and the PR process.

This project follows [Semantic Versioning](https://semver.org/). Every PR that changes user-visible behaviour must include a [CHANGELOG.md](CHANGELOG.md) entry under `[Unreleased]`.

## Disclaimer

MacNoise is intended for **authorized** security testing, EDR validation, and detection engineering on systems you own or have explicit written permission to test. The authors assume no liability for misuse.

# AI Code Policy

AI Code contributions are fine, but please keep in mind that code review is currently going to be a human-led process which means there is only so much code we can review. Please limit PRs to a specific fix, or new telemetry module. PRs with extensive changes are likely going to be closed. 