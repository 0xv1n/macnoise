# AI guidance for MacNoise

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing the repository. It defines the supported contribution paths, validation gates, and release conventions.

## Product boundary

MacNoise generates real macOS activity for authorized detection testing. Go primitives and native adapters attempt operating-system actions and report observed results. YAML scenarios compose those operations into preflighted, typed flows.

Do not replace real activity with synthetic success events. Expected environmental denials are useful observations. Failures in MacNoise, event output, or cleanup fail the invocation.

## Architecture

| Layer | Location | Responsibility |
|---|---|---|
| CLI | `cmd/macnoise` | Commands, flags, emitters, reports, and signal handling |
| Public module API | `pkg/module` | Factories, typed parameters and outputs, catalog metadata, events |
| Operations | `modules/<category>` | Real operating-system activity and precise cleanup |
| Runtime | `internal/runner` | Validation, scenario dataflow, lifecycle, workspace, cleanup |
| Output and audit | `internal/output`, `internal/audit` | Telemetry schema 2.0 and OCSF audit records |
| Scenarios | `configs/scenarios` | Version 1 compositions and reusable recipes |

The registry stores factories. Every invocation receives a new module instance. Runtime state must not be global or shared.

## Contracts to preserve

- Keep module metadata and registration portable. Isolate native implementation code behind Darwin build tags only when needed.
- Declare all parameters and outputs with authoritative types. Unknown or invalid values fail before preview or execution.
- Give every telemetry event one valid outcome and one typed subject. Propagate every emitter error.
- Redact sensitive parameters and outputs before managed logging.
- Let scenarios own dataflow, failure policy, workspace lifetime, and reverse cleanup.
- Use explicit `{input: name}` and `{output: step.name}` mappings. Do not add implicit interpolation, ambient environment expansion, or destructive globbing.
- Treat cancellation independently of `on_error`. It always stops execution.
- Make cleanup ownership exact. Preserve pre-existing and subsequently modified state or report a conflict.
- Keep audit logging observational. Enabling it must not change execution decisions.

## Before adding code

Check the generated [module catalog](docs/module-catalog.md). If existing primitives can express the behavior, add a YAML recipe instead of another Go module.

For a defect, reproduce it through the CLI or runner boundary before fixing the lower-level cause. Put portable logic in untagged files so it runs in the normal unit suite. Use real macOS integration tests for actual system effects.

Run `make generate-catalog` after changing catalog metadata. Never edit the generated catalog, `CHANGELOG.md`, or the fallback version manually.

Deferred EDR alert assertion infrastructure is outside this repository. MacNoise reports activity it attempted and observed; it does not decide whether a particular security product should alert.
