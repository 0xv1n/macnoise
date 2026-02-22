# Contributing to MacNoise

Thanks for your interest in contributing! This guide covers how to add new telemetry modules, the code style expectations, and the PR process.

## Adding a New Module

### Step-by-step

1. **Choose a category** — see `pkg/module/category.go` for the list. If you need a new category, add it there.

2. **Create your file** — `modules/<category>/<name>.go`. Use an existing module as a reference, e.g., `modules/network/connect.go`.

3. **Implement the `Generator` interface** (`pkg/module/interface.go`):

```go
type Generator interface {
    Info() ModuleInfo
    ParamSpecs() []ParamSpec
    CheckPrereqs() error
    Generate(ctx context.Context, params Params, emit EventEmitter) error
    DryRun(params Params) []string
    Cleanup() error
}
```

4. **Register via `init()`**:

```go
func init() {
    module.Register(&myModule{})
}
```

5. **Add the blank import** in `cmd/macnoise/main.go`:

```go
_ "github.com/0xv1n/macnoise/modules/mynewcategory"
```

6. **Write tests** — add `modules/<category>/<name>_test.go` with `//go:build integration && darwin`.

### Checklist

- [ ] Implements all 6 methods of `Generator`
- [ ] `Info()` has accurate `Category`, `Tags`, `Privileges`, and `MITRE` entries
- [ ] `ParamSpecs()` documents every accepted parameter with defaults and examples
- [ ] `CheckPrereqs()` returns a clear error when requirements aren't met
- [ ] `DryRun()` describes every action without executing side-effects
- [ ] `Cleanup()` fully reverts any persistent changes
- [ ] Module emits events via `emit()`, never writes directly to stdout
- [ ] Registered in `cmd/macnoise/main.go` via blank import
- [ ] Integration test file added
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

## Code Style

- Run `gofmt -w .` before committing
- Run `go vet ./...` — fix all warnings
- Run `golangci-lint run ./...` — address all findings
- No global mutable state outside of the registry
- Prefer returning errors over `log.Fatal`

## Emit Events Correctly

```go
// Good — use output.NewEvent and the emit callback
ev := output.NewEvent(info, "event_type", success, "message")
ev = output.WithDetails(ev, map[string]any{"key": "value"})
emit(ev)

// Bad — never write to stdout/stderr directly from a module
fmt.Println("something happened")
```

## Audit Logging (OCSF)

MacNoise writes a second output stream alongside telemetry events: structured audit records in [OCSF 1.7.0](https://schema.ocsf.io/) JSONL format via `internal/audit/`. These records capture what MacNoise itself did — which modules ran, prereq and cleanup outcomes, timing, and MITRE mappings — rather than the telemetry events that modules produce for EDR consumption.

### Modules don't need to do anything

The runner automatically wraps the `emit` callback with `Logger.WrapEmitter()` when `--audit-log` is active. Every `TelemetryEvent` emitted by your module is intercepted, classified, and written to the audit file without any change to module code. Lifecycle records (prereq check, cleanup, dry-run outcome) are also written by the runner — no module-level calls to `audit.Logger` are needed or appropriate.

### Adding a new event type to the classifier

`internal/audit/classify.go` maps `(category, eventType)` pairs to OCSF class and activity identifiers. If your module emits a new `eventType` string that should resolve to a specific OCSF activity (e.g. `Read` instead of the default `Create` for a file module), add a case to the relevant helper:

```go
// In classify.go
func fileActivity(eventType string) (int, string) {
    switch eventType {
    case "my_read_event":
        return 4, "Read"
    // ...
    }
}
```

If your new event type already maps correctly through its category (e.g. a new file module emitting `"write"` already reaches `fileActivity`), no change to `classify.go` is needed.

### OCSF class mapping

| macnoise category | OCSF class UID | OCSF class name |
|-------------------|----------------|-----------------|
| `network` | 4001 | Network Activity |
| `network` (HTTP event types) | 4002 | HTTP Activity |
| `network` (DNS event types) | 4003 | DNS Activity |
| `process` | 1007 | Process Activity |
| `file`, `plist` | 1001 | File System Activity |
| `tcc`, `xpc` | 6003 | API Activity |
| `endpoint_security` | 1001 or 1007 | Inferred from event type string |
| `service` | 1006 | Scheduled Job Activity |

A new category requires a new `case` in the top-level `Classify()` switch and a row in this table.

### Record structure

Each record is an `audit.Record` (`internal/audit/record.go`). Key fields and their sources:

| Field | Source |
|-------|--------|
| `class_uid` / `activity_id` | `Classify(ev.Category, ev.EventType)` |
| `time` | Epoch milliseconds at write time |
| `status_id` | `1` (success) or `2` (failure) from `ev.Success` |
| `metadata.correlation_uid` | Shared run ID across all records in one execution |
| `actor` | PID, executable path, and username of the macnoise process |
| `attacks[]` | MITRE entries from `ModuleInfo.MITRE` |
| `unmapped` | Module name, category, params, and lifecycle outcome fields |

### Checklist for audit-aware contributions

- [ ] If your module emits a new `eventType` not handled by the existing category switch in `classify.go`, add a case
- [ ] Do **not** call `audit.Logger` methods directly from module code — the runner owns the logger lifecycle
- [ ] If you add a new `Category`, add a `case` in `Classify()` and update the class mapping table above
- [ ] If you extend `LifecycleData` or `Record`, update the corresponding serialisation in `logger.go`
- [ ] Verify audit records are valid OCSF by checking that `class_uid`, `category_uid`, `activity_id`, and `type_uid` are consistent (`type_uid = class_uid * 100 + activity_id`)

## PR Process

**One-time setup** (after cloning):
```bash
make install-hooks
```
This installs a pre-push git hook that runs `make lint` and `make test` automatically before every push, so CI failures are caught locally first.

1. Fork the repo and create a feature branch: `git checkout -b feat/my-module`
2. Make your changes following the checklist above
3. Add an entry to `CHANGELOG.md` under `[Unreleased]` — PRs that omit this will not be merged
4. Run `make test` and `make lint` — both must pass
5. Open a PR against `main`; the PR template will guide the required description fields

## Versioning

MacNoise follows [Semantic Versioning 2.0.0](https://semver.org/).

| Change type | Version bump | Example |
|-------------|-------------|---------|
| Incompatible CLI or API change | **MAJOR** (`X.0.0`) | Removing a flag, renaming a module |
| New module, new flag, backwards-compatible feature | **MINOR** (`0.X.0`) | Adding `net_tls`, adding `--quiet` |
| Bug fix, doc update, internal refactor | **PATCH** (`0.0.X`) | Fixing a Cleanup regression |

Rules:
- While the project is `0.x.y`, minor-bump for breaking changes is acceptable.
- Every merged PR that changes user-visible behaviour **must** include a `CHANGELOG.md` entry under `[Unreleased]`.
- Releases are tagged `vX.Y.Z` on `main` by a maintainer. The release commit moves the `[Unreleased]` block to a dated version section in `CHANGELOG.md`. **No source file edit is needed to set the version** — the build system injects it automatically from the git tag via LDFLAGS (`-X main.version=<tag>`). The canonical link point is `cmd/macnoise/version.go`.