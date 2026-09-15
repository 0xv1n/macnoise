# Contributing to MacNoise

MacNoise accepts focused changes that improve real macOS telemetry generation, scenario composition, or the runtime that connects them.

## Choose the right contribution path

| Goal | Path |
|---|---|
| Add a new operating-system action | Add a primitive or native adapter under `modules/<category>/` |
| Combine existing actions into a technique or intrusion flow | Add a version 1 YAML recipe or scenario under `configs/scenarios/` |
| Fix lifecycle, validation, output, or CLI behavior | Add a regression test in the owning package, then change that package |
| Correct documentation or metadata | Update the source metadata and run `make generate-catalog` |

Do not add a Go module when existing primitives can express the behavior. Prefer a YAML recipe for composition.

## Primitive modules

Start from [the module template](docs/templates/module.go.tmpl) and an existing module in the same category.

1. Implement all six methods of `module.Generator`.
2. Register a factory that returns a new instance. Runtime state must never be shared between invocations.
3. Declare every parameter with a type, default, bounds or choices, and sensitivity in `ParamSpecs()`.
4. Keep metadata and registration portable. Put only native implementation details behind Darwin build tags.
5. Attempt the real operating-system action before reporting its result. Synthetic success events are not substitutes for real activity.
6. Emit events through the provided callback and propagate its error.
7. Reverse only changes owned by that invocation. Preserve unrelated or subsequently changed state and report conflicts.

Every event needs exactly one outcome and one typed subject:

| Outcome | Meaning |
|---|---|
| `executed` | The attempted action completed as claimed |
| `denied` | The environment explicitly refused the action |
| `indeterminate` | The action ran, but its result proves neither success nor denial |
| `error` | MacNoise failed to perform or observe the action |

Use `module.File`, `Process`, `Network`, `Service`, or `Resource` for the subject. Mark secret-bearing parameters and outputs as sensitive. Managed logs must never receive their original values.

If a later scenario step needs a produced value, implement `module.OutputProvider`, declare it in `OutputSpecs()`, and publish it with `module.PublishOutput`. Use `module.WorkspaceFromContext(ctx)` only for invocation artifacts that must survive until scenario cleanup.

Add portable unit tests for metadata, validation, failure classification, and ownership logic. Add `//go:build integration && darwin` tests for real macOS effects. A skipped root-only or GUI-only test is a stated coverage limit, not proof that the path works.

When an event type needs a non-default OCSF activity, update `internal/audit/classify.go` and its tests. Modules must not call the audit logger directly.

A new category also needs a constant in `pkg/module/category.go`, blank imports in both CLI commands under `cmd/`, and an OCSF classifier mapping.

## Scenarios and recipes

Start from [the scenario template](docs/templates/scenario.yaml). Scenario files use `version: 1` and are strictly validated before any mutation.

- Give each data-producing step an `id`.
- Reference declared scenario inputs with `{input: name}`.
- Reference declared module outputs with `{output: step.name}`.
- Use local `include` steps for reusable recipes.
- Set `on_error: continue` only for coverage sweeps. Connected flows should stop on failure.
- Do not add shell expansion, ambient environment expansion, implicit destructive globs, or a template language.

Run every changed stock scenario with `--dry-run`. Tests validate all files under `configs/scenarios/` against the complete portable catalog.

## Core changes

Start with a test that reproduces the behavior through the closest public entry point. Preserve these boundaries:

- The registry stores factories, not singleton instances.
- Parameter normalization and complete scenario preflight happen before mutation.
- Cancellation always stops a scenario and remains recognizable through `errors.Is`.
- Scenario cleanup runs in reverse order with an independent deadline.
- Audit logging records decisions but never controls them.
- JSONL stdout remains machine-readable. Diagnostics and previews go to stderr.

## Generated reference

[`docs/module-catalog.md`](docs/module-catalog.md) is generated from live registry metadata. After changing module metadata, parameters, outputs, categories, or registration, run:

```bash
make generate-catalog
```

The unit suite fails when the tracked reference is stale. Do not edit it by hand.

## Validation

Run the checks appropriate to the change, with the full local gate before opening a PR:

```bash
make generate-catalog
make test
make lint
go vet ./...
GOOS=darwin GOARCH=amd64 go build ./cmd/macnoise
GOOS=darwin GOARCH=arm64 go build ./cmd/macnoise
```

Real-operation changes also require the race-enabled integration suite on macOS:

```bash
go test -tags integration -race -count=1 ./...
```

On a host without a CGO toolchain, `-race` cannot build. Run `go test -count=1 ./...` locally and require the race-enabled CI and macOS jobs before merge.

## Pull requests

Keep the description short: state the change and why in one or two sentences, then list validation. Call out a compatibility break or unverified root/GUI path directly.

This repository squash-merges PRs. The PR title becomes the commit Release Please reads, so use Conventional Commits:

| Title | Release effect after 1.0 |
|---|---|
| `fix: ...`, `perf: ...`, `refactor: ...`, `revert: ...` | Patch |
| `feat: ...` | Minor |
| `type!: ...` | Major |
| `docs:`, `test:`, `ci:`, `build:`, `chore:` | No bump on their own |

Use the `!` in the title for a breaking change so it survives the squash merge. `CHANGELOG.md` and `cmd/macnoise/version.go` are maintained by Release Please and must not be edited manually.

Install the repository hooks once with `make install-hooks` if your platform supports them.
