<div style="text-align: center;">
  <img src="macnoise.png" alt="MacNoise logo" style="max-width: 100%; height: auto; display: block; margin: 0 auto;">
</div>

---

[![CI](https://github.com/0xv1n/macnoise/actions/workflows/ci.yaml/badge.svg)](https://github.com/0xv1n/macnoise/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/0xv1n/macnoise)](https://github.com/0xv1n/macnoise/releases/latest)

# MacNoise

MacNoise generates real macOS activity for EDR validation and detection engineering. Run individual modules or YAML scenarios to exercise network connections, file writes, process execution, persistence, TCC access, and other behaviors against your security controls.

For background on the motivation and design, see the [release blog post](https://0xv1n.github.io/posts/macnoise/).

## Before you run

MacNoise is intended for **authorized** security testing on systems you own or have explicit written permission to test. Modules perform the real activity they describe. They are not sandboxed, and some actions can irreversibly delete or alter system and user data. Review module behavior and dry-run output before execution. You are responsible for target selection, authorization, and consequences. The authors assume no liability for misuse.

## Quick start

Build from a checkout with Go 1.24 or later and Make:

```bash
make build
```

Run the binary on macOS. To cross-compile, use `make build-amd64` for Intel Macs, `make build-arm64` for Apple silicon, or `make release` for both.

List modules and inspect the one you want to run:

```bash
./macnoise list
./macnoise info file_create
```

Preview the parameters, then execute the same command without `--dry-run`:

```bash
./macnoise run file_create --param count=1 --dry-run
./macnoise run file_create --param count=1
```

The second command creates a file, emits telemetry, and runs cleanup. To preview a connected sequence of modules:

```bash
./macnoise scenario configs/scenarios/file_flow.yaml --dry-run
```

[Run scenarios](#run-scenarios) to connect module outputs, [capture output](#capture-output-and-audit-records) for analysis, or [retain artifacts](#retain-artifacts) for later scans.

## Find a module

The generated [module catalog](docs/module-catalog.md) lists every module, parameter, output, event type, privilege, and ATT&CK mapping. Category guides explain platform requirements and module behavior:

| Category | Description |
|----------|-------------|
| [network](modules/network/README.md) | TCP connections, HTTP, listeners, reverse shells, DNS, and TLS |
| [process](modules/process/README.md) | Execution, signal delivery, dylib injection, Gatekeeper bypass, and osascript |
| [file](modules/file/README.md) | Discovery, reads, copies, creation, modification, archiving, hiding, and decoy encryption |
| [tcc](modules/tcc/README.md) | Full Disk Access, Contacts, Accessibility, and Screen Recording probes |
| [credential](modules/credential/README.md) | Native credential-store access |
| [volume](modules/volume/README.md) | Disk-image creation and mounted-volume lifecycle |
| [service](modules/service/README.md) | Launchd enumeration, LaunchAgent and LaunchDaemon persistence, cron, shell profiles, and Login Items |
| [plist](modules/plist/README.md) | Plist creation and modification |
| [evasion](modules/evasion/README.md) | Log clearing, timestomping, history removal, and masquerading |

Use `./macnoise list --category network` to filter the list. To execute a category or every registered module, use `./macnoise run --category network` or `./macnoise run --all`.

## Commands

```
macnoise run <module> [--param key=val ...]   Run a specific module
macnoise run --category <cat>                 Run all modules in a category
macnoise run --all                            Run all modules
macnoise list [--category <cat>]              List modules
macnoise info <module>                        Show module details, params, MITRE
macnoise scenario <file.yaml> [--input key=val] [--report report.json]
                                                Run a YAML scenario
macnoise categories                           List categories with counts
macnoise version                              Print version
```

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `human` | Output format: `human` or `jsonl` |
| `--output` | (none) | Write output to file (in addition to stdout) |
| `--verbose` | false | Currently accepted without changing output |
| `--dry-run` | false | Preview actions without executing |
| `--no-cleanup` | false | [Retain artifacts](#retain-artifacts) after execution |
| `--timeout` | `30` | Per-module timeout in seconds. `0` disables the timeout |
| `--audit-log` | (none) | Write OCSF 1.7.0 audit records to a JSONL file |
| `--config` | (none) | Load defaults from a YAML config file |
| `--run-id` | generated | Set the correlation identifier for this run |

## Retain artifacts

By default, MacNoise runs module cleanup after execution. Cleanup removes artifacts that the invocation created and still owns. It cannot reverse completed network, process, or destructive activity.

To validate that your stack detects persistence itself, leave the artifact in place while the scan runs. Examples include a LaunchAgent in `~/Library/LaunchAgents`, a cron entry, and a modified shell profile:

```bash
./macnoise run svc_launch_agent --no-cleanup
```

Each module that skips cleanup prints a diagnostic, and the audit log records `cleanup_result: skipped`. Use the [module catalog](docs/module-catalog.md) and category guides to review the artifacts a module creates.

**You are responsible for removing these yourself.** Re-running the same module without the flag will clean up only what that run created, not what a previous `--no-cleanup` run left behind.

## Capture output and audit records

MacNoise emits its own descriptions of attempted actions to stdout. Your security controls collect their own telemetry from the activity on the host. Use `--format jsonl` for structured MacNoise events and `--output` to append a copy to a file:

```bash
./macnoise scenario configs/scenarios/file_flow.yaml --format jsonl --output /tmp/events.jsonl
```

Add `--audit-log` to record module execution, prerequisite and cleanup outcomes, and MITRE mappings in [OCSF 1.7.0](https://schema.ocsf.io/) JSONL:

```bash
./macnoise scenario configs/scenarios/file_flow.yaml --audit-log /tmp/audit.jsonl
```

Run identifiers, previews, and cleanup diagnostics go to stderr. Every telemetry event carries an `outcome` and one typed `subject` in schema 2.0. The subject identifies the file, process, network endpoint, service, or resource involved:

| `outcome` | Meaning | Human marker |
|---|---|---|
| `executed` | The action ran and did what the module claims | `[+]` |
| `denied` | The action ran and the environment refused it | `[-]` |
| `indeterminate` | The action ran, but nothing can be concluded | `[?]` |
| `error` | MacNoise itself failed to carry the action out | `[!]` |

A denied TCC probe records an action that the environment refused. An `error` means MacNoise failed to carry out the action. The audit log records the outcome at `unmapped.outcome`. Parameters declared sensitive are replaced with `[REDACTED]` in managed audit parameters, and command-line identity redacts `--param` and `--input` values.

The audit log appends records across runs. Use `--run-id` to set a correlation identifier, or let MacNoise generate one. For event classification details, see [CONTRIBUTING.md](CONTRIBUTING.md#primitive-modules).

## Run scenarios

Scenarios connect modules into ordered sequences in one YAML file. Preview a scenario, then execute it and write a report:

```bash
./macnoise scenario configs/scenarios/file_flow.yaml --dry-run
./macnoise scenario configs/scenarios/file_flow.yaml --report /tmp/report.json
```

Choose a stock scenario from `configs/scenarios/`:

| File | Description |
|------|-------------|
| `network_only.yaml` | Composed TCP, listener, DNS, HTTP beacon, and HTTP exfiltration operations |
| `edr_validation.yaml` | Comprehensive EDR detection coverage |
| `full_sweep.yaml` | All categories |
| `lazarus_group.yaml` | Lazarus Group: dylib injection, service discovery, reverse shell, LaunchAgent persistence |
| `amos_atomic_stealer.yaml` | AMOS / Atomic Stealer: MaaS infostealer, Gatekeeper bypass, keychain dump, ZIP exfil, backdoor persistence |
| `clickfix.yaml` | ClickFix: obfuscated one-liner pasted into Terminal, base64 decode, second-stage fetch, LaunchAgent persistence |
| `ransomware.yaml` | Ransomware impact: stage plaintext decoys, encrypt them, then drop a ransom note |
| `discovery.yaml` | Composed argv-based system, account, network, and security software discovery recipes |
| `process_chain.yaml` | Three-process shell chain built from an explicit argument vector |
| `file_flow.yaml` | Connected create, modify, bounded discovery, read, copy, and archive flow |
| `mounted_execution.yaml` | Create and execute a payload from an observed disk-image mount point |

The AMOS scenario cites the threat reports used for its sequence and step annotations. The Lazarus scenario groups representative macOS techniques into one sequence. Each step comment names the MITRE ATT&CK technique that it exercises.

Compare the execution report with the telemetry and alerts collected by your security controls. A missing alert needs investigation against the action's outcome and your detection rules.

### Write a scenario

Scenario files use `version: 1`. This example passes a typed input to `file_create`, then archives its declared `path` output. Save it as `archive.yaml`:

```yaml
version: 1
name: Archive one generated artifact
on_error: stop
inputs:
  content:
    type: string
    required: true
steps:
  - id: create
    module: file_create
    params:
      filename: artifact.txt
      content:
        input: content
  - id: archive
    module: file_archive
    params:
      source_path:
        output: create.path
      tool: tar
      output_path: /tmp/macnoise_example.tar.gz
outputs:
  archive:
    output: archive.path
```

Supply the input and preview the sequence:

```bash
./macnoise scenario archive.yaml --input content=example --dry-run
```

MacNoise validates parameter types, names, and references before preview or execution. Only declared module outputs can be referenced. `on_error` defaults to `stop`. Set it to `continue` when later module invocations should run after a failure. Cancellation always stops the run.

Reuse local scenarios with an `include` step. Includes resolve relative to the including file, stay beneath the root scenario directory, reject cycles, and allow at most eight levels. MacNoise creates one private workspace for the run and cleans invoked modules in reverse order. Cleanup removes generated artifacts unless you use `--no-cleanup`, so paths in a report may no longer exist after execution.

Start from the [scenario template](docs/templates/scenario.yaml) for typed inputs, outputs, and connected dataflow.

## Version 1 compatibility

Version 1.0 defines the supported CLI commands and flags, module names and contracts, scenario schema 1, telemetry schema 2.0, and scenario-report schema 1.0. Future incompatible changes to those interfaces require a new major release.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the primitive, scenario, and core-change paths.

Releases use [release-please](https://github.com/googleapis/release-please). Use a [Conventional Commit](https://www.conventionalcommits.org/) PR title, such as `feat: add net_tls module` or `fix: correct beacon jitter`, to describe the change in the changelog.

### AI code policy

AI-assisted contributions are welcome. Human review capacity is limited, so keep each PR focused on a specific fix or telemetry module. Broad changes may be closed.
