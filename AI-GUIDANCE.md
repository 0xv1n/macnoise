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
│   └── xpc/               # 1 module:  xpc_enumerate
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
| `internal/output/event.go` | `NewEvent` constructs a `TelemetryEvent` with an explicit outcome and typed subject; `NormalizeEvent` applies authoritative identity and UTC time; `WithDetails`, `WithError`, `WithOutcome`, `DetailStr`, `DetailInt` helpers; `SchemaVersion = "2.0"`; `CurrentProcessContext` |

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
| `internal/prereqs/checker.go` | `IsMacOS`, `IsRoot`, `IsAdmin`, `HasCommand`; error-returning variants `CheckMacOS`, `CheckRoot`, `CheckCommand`; called from module `CheckPrereqs(ctx, params)` implementations |

### Configs and Scenarios

| File | Purpose |
|------|---------|
| `configs/defaults.yaml` | Example config file — set `default_format`, `default_timeout`, `audit_log`, `output_file` |
| `configs/scenarios/network_only.yaml` | Selected connection, listener, DNS, and beacon modules |
| `configs/scenarios/edr_validation.yaml` | Broad EDR detection coverage across process, network, file, persistence, TCC |
| `configs/scenarios/full_sweep.yaml` | Broad sweep across all categories, excluding root-only modules |
| `configs/scenarios/lazarus_group.yaml` | DPRK-style implant chain (T1574.006, T1071, T1059.004, T1543) |
| `configs/scenarios/amos_atomic_stealer.yaml` | AMOS 2025 variant with a 10-phase infostealer kill chain |

---

## The Generator Interface

Every module is a Go struct that satisfies `module.Generator`:

```go
type Generator interface {
    Info()         ModuleInfo     // Static metadata: name, category, tags, privileges, MITRE
    ParamSpecs()   []ParamSpec    // Accepted parameters with defaults and examples
    CheckPrereqs(ctx context.Context, params Params) error // Fail fast if requirements aren't met
    Generate(ctx context.Context, params Params, emit EventEmitter) error
    DryRun(params Params) []string // Human-readable description of actions; no side-effects
    Cleanup(ctx context.Context) error // Fully revert persistent changes made by Generate
}
```

**Registration** — every module file has an `init()` function:
```go
func init() {
    module.Register(func() module.Generator { return &myModule{} })
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
DryRun mode?
  └─ yes → print actions, write audit dry-run record, return
CheckPrereqs(ctx, params)
  └─ fail → write audit lifecycle record, return error
Generate(ctx, params, auditWrappedEmit)
  └─ each emit() call → telemetry event to stdout/file
                      → audit.LogEvent() (if --audit-log active)
Cleanup(cleanupCtx)
  └─ write audit lifecycle record with full outcome data
```

The `opts.AuditLog` field (`*audit.Logger`) is the only coupling between the runner and the audit system. If it is `nil`, no audit records are written and module code is unchanged.

---

## Event Emission Pattern

Modules **never** write to stdout directly. All output flows through the `emit` callback:

```go
// Construct
ev := output.NewEvent(info, "event_type", module.OutcomeExecuted, module.File(path), "initial message")

// Decorate the event.
ev.Message = "final message"
ev = output.WithDetails(ev, map[string]any{"key": "value"})

// MacNoise itself failed.
ev = output.WithError(ev, err)

// The action ran but the environment refused or did not answer it.
ev = output.WithOutcome(ev, module.OutcomeDenied, err)

// Propagate output and audit failures.
if err := emit(ev); err != nil {
    return err
}
```

`output.NewEvent` requires an explicit `Outcome` and exactly one typed `Subject`. Use `module.File`, `module.Process`, `module.Network`, `module.Service`, or `module.Resource`. The runner normalizes schema version, module identity, MITRE data, process context, and one UTC timestamp before telemetry and audit writers receive the event.

**Picking between `WithError` and `WithOutcome`.** A refused TCC probe, a connection to a closed port, and a missing target are all telemetry this tool exists to produce, not faults. Use `OutcomeDenied` when the environment refused, `OutcomeIndeterminate` when nothing can be concluded, and `WithError` only when MacNoise itself failed.

Every event must set one of the four valid outcomes. Missing outcomes and subjects fail at the runner boundary before any writer receives the event.

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

- **Target execution platform**: macOS (darwin). Other platforms support the complete catalog, scenario validation, and dry runs.
- **Development environment**: Cross-compilation from any OS is supported via `GOOS=darwin`.
- **Darwin-only code**: Keep module metadata and registration portable, and isolate native syscall implementations behind `//go:build darwin` when required.
- **CGO**: Not used. The build is pure Go.
- **Version injection**: `make build` passes `-ldflags "-X main.version=$(VERSION)"`. Do not hardcode version strings.
- **Unit tests run on any OS**: `go test ./...` covers the portable catalog and all cross-platform packages.
- **Integration tests**: Tagged `//go:build integration && darwin` and require a real macOS system.

```bash
# Cross-compile from Windows/Linux
GOOS=darwin GOARCH=arm64 go build ./cmd/macnoise

# Unit tests (any OS)
go test ./...

# Lint
golangci-lint run ./...
```

---

## Adding a New Module — Checklist

1. Create `modules/<category>/<name>.go`.
2. Define a private struct and implement all 6 `Generator` methods.
3. Populate `ModuleInfo` accurately — `Name` (unique, snake_case), `Category`, `Tags`, `Privileges`, `MITRE`.
4. Add `func init() { module.Register(func() module.Generator { return &myStruct{} }) }`.
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
| Params access | Use the typed `params.String`, `Int`, `Bool`, `Strings`, or `Paths` accessor that matches `ParamSpecs()` |
| Build tags | Keep metadata and registration portable; isolate Darwin-only implementation code behind `//go:build darwin` |
| File names | One module per file, named after the module (`net_connect.go` → `net_connect` module) |
| Package names | Module packages use the category name (e.g. `package network`), not the module name |

---

## Common Mistakes to Avoid

- **Writing to stdout from a module** — breaks JSONL output mode and bypasses the audit wrapper.
- **Calling `audit.Logger` methods from a module** — the runner owns the logger. Modules must not import `internal/audit`.
- **Hardcoding OS paths** — declare a path parameter and use `params.String(...)` so callers can override it.
- **Missing `Cleanup()`** — every state change in `Generate()` must be reversible. If `Cleanup()` is a no-op because nothing persists, that is fine; it must still exist.
- **Registering with a duplicate name** — `Register()` panics on collision. Module names are global and must be unique.
- **Missing blank import** — a new category package won't register its modules unless imported in `cmd/macnoise/main.go`.
- **Hiding metadata behind a darwin build tag** - keep metadata and registration portable, and put only native implementation code behind `//go:build darwin`.

---

## Where Things Are NOT

- There is no dependency injection framework — the registry and logger are passed explicitly.
- There is no HTTP server or daemon mode — MacNoise runs, generates events, and exits.
- There is no database — all state is ephemeral for the duration of a run.
- There are no generated files — no protobuf, no mockgen, no code generation.
