---
name: verify-macnoise
description: Verify MacNoise CLI discovery, previews, execution, scenarios, and output through real user commands.
---

# Verify MacNoise

## Launch

From the repository root on macOS, create independent scratch and evidence directories: `RUN=$(mktemp -d "${TMPDIR:-/tmp}/macnoise-verify.XXXXXX")` and `EVIDENCE="$PWD/.tmp/macnoise-proof-$(date +%Y%m%d%H%M%S)-$$"; mkdir -p "$EVIDENCE"`. Save both paths for cleanup. Build the current checkout with `go build -o "$RUN/macnoise" ./cmd/macnoise`. Each command is a short-lived process; no server or seed data is needed. On Windows use a unique scratch directory and `go build -o <scratch>/macnoise.exe ./cmd/macnoise`; only cross-platform CLI paths are verified there. macOS is required to prove macOS telemetry.

## Doctor

Run `"$RUN/macnoise" version` and `"$RUN/macnoise" list --category network`; require a successful exit and `net_connect` in the list. The binary must be the one just built, not a pre-existing binary on PATH. Consult `features/README.md` before selecting a journey.

## Drive

Use the exact CLI commands and preconditions in the feature map. Execute only on a disposable machine or environment suitable for the selected module: commands can create real telemetry, access files, launch processes, or alter system state. Do not run broad categories or scenarios blindly. Do not run concurrent state-changing journeys against shared host paths. Use isolated paths, unique output and audit logs, and explicitly selected safe targets. Never infer safety from `--dry-run`: inspect its actual effects and relevant module behavior.

## Evidence

Record the exact commands, stdout, stderr, exit codes, and resulting state in `$EVIDENCE`; include feature and entry point. Capture both action and result, and independently inspect files, network listeners, or other side effects when applicable. Exercise the real CLI, not internal setters or test-only endpoints. Only mock an external boundary already isolated by production code. State platform and unmet preconditions; a preview does not prove real telemetry.

## Cleanup

Wait for each process started by this run; interrupt it gracefully if needed and never kill by process name. Remove only the scratch directory and artifacts created by the run after checking their paths. Preserve `$EVIDENCE` and confirm it remains readable. Avoid `--no-cleanup` unless the feature specifically requires it and the run has an explicit removal plan. Some modules affect shared host state; verify their cleanup independently.

## Helpers

No helper scripts are required.
