## Summary

<!-- One or two sentences: what does this PR do and why? -->

## Type of change

<!-- Check all that apply -->

- [ ] New telemetry module
- [ ] Bug fix
- [ ] Enhancement to an existing module
- [ ] Scenario / config change
- [ ] Documentation update
- [ ] Refactor / internal improvement

## Telemetry details

<!-- Required for new or modified modules. Skip for doc-only changes. -->

**What telemetry does this generate?**

<!-- Describe the events emitted and what system activity they represent. -->

**MITRE ATT&CK mapping(s)**

| Technique ID | Name |
|--------------|------|
| T<!-- e.g. T1071.001 --> | <!-- Web Protocols --> |

**Privilege requirements**

- [ ] None (runs as standard user)
- [ ] Root / `sudo`
- [ ] TCC permission(s) required: <!-- list them, e.g. FDA, Contacts -->
- [ ] macOS system extension / SIP interaction

**How does `Cleanup()` revert changes?**

<!-- Describe every persistent side-effect this module introduces and how Cleanup removes it. -->

## Module implementation checklist

<!-- Required for new modules. Skip for doc-only / config-only changes. -->

- [ ] Implements all 6 methods of the `Generator` interface
- [ ] `Info()` has accurate `Category`, `Tags`, `Privileges`, and `MITRE` entries
- [ ] `ParamSpecs()` documents every accepted parameter with defaults and examples
- [ ] `CheckPrereqs()` returns a clear error when requirements aren't met
- [ ] `DryRun()` describes every action without executing side-effects
- [ ] `Cleanup()` fully reverts any persistent changes
- [ ] Module emits events via `emit()`, never writes directly to stdout
- [ ] Registered in `cmd/macnoise/main.go` via blank import
- [ ] Integration test file added (`modules/<category>/<name>_test.go`)

## General checklist

- [ ] `make test` passes
- [ ] `make lint` passes (no `go vet` or `golangci-lint` warnings)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Targets the `main` branch
- [ ] PR scope is limited to a single fix or module (see AI Code Policy in CONTRIBUTING.md)

## Testing notes

<!-- How did you verify this works? Include any manual steps, edge cases tested, or known limitations. -->
