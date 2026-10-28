# Scenarios

Users execute a YAML scenario and inspect its report.

## Sub-features
- Run a connected file flow using isolated input paths.

## How to get to it (user POV)
- `scenario configs/scenarios/file_flow.yaml` with input overrides and a report.

## Driving it with the CLI
Preconditions: macOS, `tar`, and a fresh `$RUN` directory. Inspect the scenario before execution.
- Run `"$RUN/macnoise" scenario configs/scenarios/file_flow.yaml --input base_dir="$RUN/files" --input copy_dir="$RUN/copies" --input archive_path="$RUN/archive.tar.gz" --report "$EVIDENCE/report.json"`. Capture command output and exit code. Inspect the report for step outcomes and outputs, and independently inspect the final state of the isolated paths after the command returns.

## Gotchas
- Default paths are shared under `/tmp`; override all three. Cleanup may remove the artifacts before the command returns, so do not claim archive contents were verified if they were not observed.
