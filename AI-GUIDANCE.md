# AI Guidance — MacNoise

This document is written for AI assistants (Claude, Codex, GPT, Gemini, etc.) working on this repository. Read it before making any changes. It describes the project's purpose, package structure, key files, design patterns, and conventions.

---

## What This Project Is

**MacNoise** is a modular macOS telemetry noise generator for EDR testing and security research. It generates *real* system events — network connections, file writes, process spawns, plist mutations, TCC permission probes, and more — so security teams can validate that their EDR, SIEM, and firewall tooling detects what it is supposed to detect.

It is **not malware**. It does not exfiltrate data, install payloads, or persist itself without explicit operator direction. All modules are reversible and include a `Cleanup()` step.

The primary output of a module run is a stream of `TelemetryEvent` records (JSON or human-readable). An optional secondary output is a structured OCSF 1.7.0 audit log (`--audit-log`) recording what MacNoise itself did.

---

## Repository Layout

```
macnoise/
├── cmd/macnoise/          # CLI entry point (Cobra)
├── pkg/module/            # Generator interface + registry (public API)
├── internal/
│   ├── audit/             # OCSF 1.7.0 audit logging
│   ├── config/            # YAML config loading
│   ├── output/            # Event formatting and emission
│   ├── prereqs/           # OS/privilege/command helpers
│   └── runner/            # Module execution orchestration
├── modules/
│   ├── network/           # 5 modules: net_connect, net_listen, net_beacon, net_dns, net_revshell
│   ├── process/           # 3 modules: proc_spawn, proc_signal, proc_inject
│   ├── file/              # 2 modules: file_create, file_modify
│   ├── tcc/               # 2 modules: tcc_fda, tcc_contacts
│   ├── endpoint_security/ # 2 modules: es_file, es_process
│   ├── service/           # 2 modules: svc_launch_agent, svc_launch_daemon
│   ├── plist/             # 2 modules: plist_create, plist_modify
│   └── xpc/               # 1 module:  xpc_connect
└── configs/
    ├── defaults.yaml
    └── scenarios/         # pre-built YAML scenarios
```

---

## Layer Architecture

MacNoise is structured in five distinct layers. When reasoning about where a change belongs, identify which layer it affects first.

| Layer | Package(s) | Responsibility |
|-------|-----------|----------------|
| **CLI** | `cmd/macnoise` | Flag parsing, command routing, emitter and audit logger construction |
| **Core** | `pkg/module` | `Generator` interface definition, module registry, category constants |
| **Modules** | `modules/<category>` | Concrete telemetry generators — one struct per module, one file per module |
| **Runtime** | `internal/runner` | Lifecycle orchestration: prereqs → generate/dry-run → cleanup; scenario parsing |
| **Output** | `internal/output` | Thread-safe event formatting (human / JSONL) and emission to writers |
| **Audit** | `internal/audit` | OCSF 1.7.0 JSONL records written in parallel with telemetry events |
| **Support** | `internal/config`, `internal/prereqs` | Config loading; OS/privilege/command prerequisite helpers |

---

## Key Files and Their Purposes

### CLI

| File | Purpose |
|------|---------|
| `cmd/macnoise/main.go` | Cobra root command; all global flags (`--format`, `--output`, `--dry-run`, `--timeout`, `--audit-log`, `--config`); `buildEmitter`, `buildAuditLogger`, `buildRunOpts` helpers; `run`, `list`, `info`, `scenario`, `categories`, `version` subcommands |
| `cmd/macnoise/version.go` | `version` string; set at compile time via `-ldflags "-X main.version=<tag>"`; never edit manually |

### Core Interface

| File | Purpose |
|------|---------|
| `pkg/module/interface.go` | `Generator` interface (6 methods); `ModuleInfo`, `ParamSpec`, `Params`, `MITRE`, `Privilege`, `TelemetryEvent`, `ProcessContext`, `EventEmitter` type definitions |
| `pkg/module/category.go` | `Category` type; `CategoryNetwork` … `CategoryXPC` constants; `AllCategories()` |
| `pkg/module/registry.go` | Global `map[string]Generator` registry; `Register`, `Get`, `All`, `ByCategory`, `ByTag`, `CategoryCounts` — all thread-safe via `sync.RWMutex` |

### Output

| File | Purpose |
|------|---------|
| `internal/output/emitter.go` | `Emitter` — wraps one or more `io.Writer` targets; `Format` type (`human` / `jsonl`); `NewEmitter`, `Emit`, `EmitFunc` |
| `internal/output/event.go` | `NewEvent` — constructs a `TelemetryEvent` pre-populated with module metadata and `ProcessContext`; `WithDetails`, `WithError`, `DetailStr`, `DetailInt` helpers; `SchemaVersion = "1.0"`; `CurrentProcessContext` |

### Runner

| File | Purpose |
|------|---------|
| `internal/runner/runner.go` | `Options` struct (`DryRun`, `Timeout`, `Verbose`, `AuditLog`); `RunSingle` — full lifecycle for one module; `RunMany` — sequential batch; `RunScenario` — YAML-driven multi-step |
| `internal/runner/scenario.go` | `Scenario` and `ScenarioStep` structs; `LoadScenario` YAML parser |

### Audit

| File | Purpose |
|------|---------|
| `internal/audit/record.go` | `Record` — the top-level OCSF JSONL struct; supporting OCSF types: `OCSFMetadata`, `OCSFProduct`, `OCSFActor`, `OCSFProcess`, `OCSFUser`, `OCSFAttack`, `OCSFTechnique`, `OCSFSubTechnique`, `OCSFTactic`, `UnmappedData`, `ScenarioUnmappedData` |
| `internal/audit/classify.go` | `Classification` struct; `Classify(category, eventType)` maps module output to OCSF class/activity IDs; private helpers `networkActivity`, `fileActivity`, `processActivity` |
| `internal/audit/logger.go` | `Logger` — mutex-protected JSONL file writer; `NewLogger`, `Close`, `WrapEmitter`, `LogEvent`, `LogLifecycle`, `LogScenario`; `LifecycleData` struct |
| `internal/audit/runid.go` | `generateRunID()` — UUID v4 correlation ID shared across all records in one execution |

### Config and Prereqs

| File | Purpose |
|------|---------|
| `internal/config/config.go` | `Config` struct (`DefaultFormat`, `DefaultTimeout`, `OutputFile`, `AuditLog`); `Defaults()`, `Load(path)` |
| `internal/prereqs/checker.go` | `IsMacOS`, `IsRoot`, `IsAdmin`, `HasCommand`; error-returning variants `CheckMacOS`, `CheckRoot`, `CheckCommand`; called from module `CheckPrereqs()` implementations |

### Configs and Scenarios

| File | Purpose |
|------|---------|
| `configs/defaults.yaml` | Example config file — set `default_format`, `default_timeout`, `audit_log`, `output_file` |
| `configs/scenarios/network_only.yaml` | All five network modules |
| `configs/scenarios/edr_validation.yaml` | Broad EDR detection coverage across process, network, file, persistence, TCC |
| `configs/scenarios/full_sweep.yaml` | All 19 modules across all categories |
| `configs/scenarios/lazarus_group.yaml` | DPRK-style implant chain (T1574.006, T1071, T1059.004, T1543) |
| `configs/scenarios/amos_atomic_stealer.yaml` | AMOS 2025 variant — 10 phases, 17 modules, full infostealer kill chain |

---

## The Generator Interface

Every module is a Go struct that satisfies `module.Generator`:

```go
type Generator interface {
    Info()         ModuleInfo     // Static metadata: name, category, tags, privileges, MITRE
    ParamSpecs()   []ParamSpec    // Accepted parameters with defaults and examples
    CheckPrereqs() error          // Fail fast if OS/privilege/command requirements aren't met
    Generate(ctx context.Context, params Params, emit EventEmitter) error
    DryRun(params Params) []string // Human-readable description of actions; no side-effects
    Cleanup() error               // Fully revert any persistent changes made by Generate
}
```

**Registration** — every module file has an `init()` function:
```go
func init() {
    module.Register(&myModule{})
}
```

**Blank imports** in `cmd/macnoise/main.go` trigger each package's `init()`:
```go
_ "github.com/0xv1n/macnoise/modules/network"
```

Adding a blank import there is the only change needed to the CLI when a new module or category package is added.

---

## Module Execution Lifecycle

`RunSingle` in `internal/runner/runner.go` drives every module through this sequence:

```
CheckPrereqs()
  └─ fail → emit error, write audit lifecycle record, return
DryRun mode?
  └─ yes → print actions, write audit dry-run record, return
Generate(ctx, params, auditWrappedEmit)
  └─ each emit() call → telemetry event to stdout/file
                      → audit.LogEvent() (if --audit-log active)
Cleanup()
  └─ write audit lifecycle record with full outcome data
```

The `opts.AuditLog` field (`*audit.Logger`) is the only coupling between the runner and the audit system. If it is `nil`, no audit records are written and module code is unchanged.

---

## Event Emission Pattern

Modules **never** write to stdout directly. All output flows through the `emit` callback:

```go
// Construct
ev := output.NewEvent(info, "event_type", false, "initial message")

// Decorate — success path
ev.Success = true
ev.Message = "final message"
ev = output.WithDetails(ev, map[string]any{"key": "value"})

// Decorate — error path
ev = output.WithError(ev, err)

// Emit
emit(ev)
```

`output.NewEvent` populates `SchemaVersion`, `Module`, `Category`, `EventType`, `MITRE`, and `ProcessContext` automatically. Modules only set `Success`, `Message`, `Details`, and `Error`.

---

## Audit Logging Architecture

The audit system is entirely transparent to module code. The runner owns it:

1. `buildAuditLogger(path)` in `main.go` creates a `*audit.Logger` if `--audit-log` is set.
2. `Logger.WrapEmitter(emit, info, params, &count)` returns a new `EventEmitter` that calls the original `emit` and then `Logger.LogEvent`.
3. The runner passes the wrapped emitter to `Generate()`.
4. After cleanup, the runner calls `Logger.LogLifecycle(...)` to write timing and outcome data.

**OCSF classification** is handled by `Classify(category, eventType)` in `classify.go`. It returns a `Classification` with `ClassUID`, `ClassName`, `CategoryUID`, `ActivityID`, and `ActivityName`. The formula `TypeUID = ClassUID * 100 + ActivityID` is used throughout.

**Correlation** — every record in a single execution shares the same `metadata.correlation_uid` (a UUID v4 generated once in `NewLogger`).

---

## Build and Platform Notes

- **Target platform**: macOS (darwin). The binary is meaningless on other OSes.
- **Development environment**: Cross-compilation from any OS is supported via `GOOS=darwin`.
- **Darwin-only code**: Modules that use `SIGSTOP`/`SIGCONT`, `launchctl`, or other Darwin-only syscalls carry a `//go:build darwin` tag.
- **CGO**: Not used. The build is pure Go.
- **Version injection**: `make build` passes `-ldflags "-X main.version=$(VERSION)"`. Do not hardcode version strings.
- **Unit tests run on any OS**: `go test ./pkg/... ./internal/...` — these packages avoid OS-specific syscalls.
- **Integration tests**: Tagged `//go:build integration && darwin` and require a real macOS system.

```bash
# Cross-compile from Windows/Linux
GOOS=darwin GOARCH=arm64 go build ./cmd/macnoise

# Unit tests (any OS)
go test ./pkg/... ./internal/...

# Lint
golangci-lint run ./...
```

---

## Adding a New Module — Checklist

1. Create `modules/<category>/<name>.go`.
2. Define a private struct and implement all 6 `Generator` methods.
3. Populate `ModuleInfo` accurately — `Name` (unique, snake_case), `Category`, `Tags`, `Privileges`, `MITRE`.
4. Add `func init() { module.Register(&myStruct{}) }`.
5. Add a blank import in `cmd/macnoise/main.go` (only needed for new *packages*).
6. If the module emits a new `eventType` string that should map to a non-default OCSF activity, add a case in `internal/audit/classify.go`.
7. Add a doc comment on the struct (required by `revive:exported` lint rule).
8. Add an integration test file with `//go:build integration && darwin`.
9. Update `CHANGELOG.md` under `[Unreleased]`.

---

## Adding a New Category

1. Add a `Category<Name> Category = "<name>"` constant in `pkg/module/category.go` and include it in `AllCategories()`.
2. Create `modules/<name>/` with at least one module file.
3. Add a blank import in `cmd/macnoise/main.go`.
4. Add a `case "<name>"` in `Classify()` in `internal/audit/classify.go` with the appropriate OCSF class UID.
5. Add a row to the OCSF class mapping table in `CONTRIBUTING.md`.
6. Add a row to the Telemetry Categories table in `README.md`.
7. Add a module README at `modules/<name>/README.md`.

---

## Code Conventions

| Convention | Detail |
|-----------|--------|
| Doc comments | Every exported symbol must have a doc comment starting with the symbol name (enforced by `revive:exported`) |
| Error returns | Never silently discard. Use `_ = f.Close()` or `defer func() { _ = f.Close() }()` for intentionally ignored returns (enforced by `errcheck`) |
| No stdout from modules | All module output goes through `emit(ev)` |
| No global state | Only the module registry (`pkg/module/registry.go`) uses package-level state; it is protected by `sync.RWMutex` |
| Params access | Always `params.Get("key", "default")` — never index `params` directly |
| Build tags | Darwin-only code: `//go:build darwin` on the first line |
| File names | One module per file, named after the module (`net_connect.go` → `net_connect` module) |
| Package names | Module packages use the category name (e.g. `package network`), not the module name |

---

## Common Mistakes to Avoid

- **Writing to stdout from a module** — breaks JSONL output mode and bypasses the audit wrapper.
- **Calling `audit.Logger` methods from a module** — the runner owns the logger. Modules must not import `internal/audit`.
- **Hardcoding OS paths** — use `params.Get(...)` with a sensible default so callers can override.
- **Missing `Cleanup()`** — every state change in `Generate()` must be reversible. If `Cleanup()` is a no-op because nothing persists, that is fine; it must still exist.
- **Registering with a duplicate name** — `Register()` panics on collision. Module names are global and must be unique.
- **Missing blank import** — a new category package won't register its modules unless imported in `cmd/macnoise/main.go`.
- **Forgetting the darwin build tag** — Darwin-only syscalls in a file without `//go:build darwin` will cause `go test ./...` to fail on the dev machine.

---

## Where Things Are NOT

- There is no dependency injection framework — the registry and logger are passed explicitly.
- There is no HTTP server or daemon mode — MacNoise runs, generates events, and exits.
- There is no database — all state is ephemeral for the duration of a run.
- There are no generated files — no protobuf, no mockgen, no code generation.
