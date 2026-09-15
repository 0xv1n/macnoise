# Migrating from v0.6.0 to v1.0.0

Version 1.0 replaces behavior-specific wrappers with reusable operating-system primitives and versioned YAML composition. There are no compatibility aliases for removed modules or categories.

## Module replacements

| Removed module | Replacement |
|---|---|
| `proc_spawn` | `proc_exec` with an explicit executable and argument list |
| `proc_discovery` | `proc_exec` through the recipes in `configs/scenarios/recipes/` or `discovery.yaml` |
| `net_beacon` | `net_http` through `recipes/http_beacon.yaml` |
| `net_exfil` | `net_http` through `recipes/http_exfil.yaml` |
| `file_browser_creds` | `recipes/browser_targets.yaml`, then `file_read` or `file_copy` |
| `file_cred_files` | `recipes/credential_targets.yaml`, then `file_read` or `file_copy` |
| `file_keychain_copy` | `recipes/keychain_targets.yaml`, then `file_copy`; use `cred_keychain` for native keychain access |
| `es_file` | Compose `file_create`, `file_modify`, `file_find`, `file_read`, `file_copy`, and `file_archive`; see `file_flow.yaml` |
| `es_process` | `proc_exec`; see `process_chain.yaml` |
| `es_mount` | `volume_create`, `volume_mount`, and `proc_exec`; see `mounted_execution.yaml` |
| `xpc_enumerate` | `svc_enumerate`, which reports the launchd domains where XPC services are registered |

The `endpoint_security` and `xpc` categories were removed. The new `credential` and `volume` categories contain native keychain and disk-image operations. Use [`module-catalog.md`](module-catalog.md) for the complete v1 module contract.

## Scenario schema v1

Every scenario now requires `version: 1`. Parsing is strict: unknown fields, invalid module parameters, unknown references, include cycles, and type mismatches fail before mutation.

Parameters are typed. Lists can be written as YAML sequences. Dataflow uses explicit mappings rather than interpolation:

```yaml
version: 1
name: Connected example
on_error: stop
inputs:
  base_dir:
    type: path
    required: true
steps:
  - id: create
    module: file_create
    params:
      base_dir:
        input: base_dir
      filename: artifact.txt
  - id: archive
    module: file_archive
    params:
      source_path:
        output: create.path
      tool: zip
outputs:
  archive:
    output: archive.path
```

Supply declared inputs with repeatable `--input key=value` flags. `on_error` defaults to `stop` and applies to each expanded module invocation. Set it to `continue` only for independent coverage sweeps. Cancellation always stops the run.

Included recipes must be beneath the root scenario directory, cannot escape with `..`, are cycle-checked, and have a maximum depth of eight.

Scenario artifacts share one private workspace. Cleanup runs in reverse invocation order. `--report <path>` writes a schema `1.0` execution report containing step and cleanup outcomes.

## Telemetry JSONL schema 2.0

Consumers must update for these changes:

- `success` was removed. Read the required `outcome` field: `executed`, `denied`, `indeterminate`, or `error`.
- Every event has exactly one typed `subject`: `file`, `process`, `network`, `service`, or `resource`.
- Module identity, MITRE metadata, process context, and timestamps are normalized by the runner.
- Output failures are returned by the invocation instead of being silently ignored.
- Sensitive parameter values are replaced with `[REDACTED]` in managed audit records.

JSONL stdout contains structured records only. Run identifiers, previews, lifecycle diagnostics, and cleanup errors are written to stderr.

## Go module API

Contributors importing `pkg/module` must update implementations:

- Register `func() module.Generator` factories instead of singleton instances.
- Change `Params` handling from `map[string]string` to declared `ParamSpec` types and typed accessors.
- Change `CheckPrereqs()` to `CheckPrereqs(context.Context, module.Params)`.
- Change `Cleanup()` to `Cleanup(context.Context)`.
- Return emitter errors from `module.EventEmitter` calls.
- Construct events with an explicit outcome and typed subject.
- Declare produced scenario values with `OutputProvider` and publish them through the invocation context.

See [the module template](templates/module.go.tmpl) and [CONTRIBUTING.md](../CONTRIBUTING.md) for the current contract.
