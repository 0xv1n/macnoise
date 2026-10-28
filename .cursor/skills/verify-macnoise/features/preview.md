# Preview

Users preview individual modules and scenarios before execution.

## Sub-features
- Preview a single module and a connected scenario.

## How to get to it (user POV)
- `run svc_launch_agent --dry-run`; `scenario configs/scenarios/file_flow.yaml --dry-run`.

## Driving it with the CLI
Preconditions: built binary; inspect the selected module and scenario for side effects before use.
- Capture `"$RUN/macnoise" run svc_launch_agent --dry-run` and `"$RUN/macnoise" scenario configs/scenarios/file_flow.yaml --dry-run --input base_dir="$RUN/files" --input copy_dir="$RUN/copies" --input archive_path="$RUN/archive.tar.gz"`, including exit codes. Expect dry-run actions and scenario status `previewed`. Check that the listed target paths were not created or changed; check all three isolated paths.

## Gotchas
- Preview output alone does not prove that no side effects occurred. Existing files at default paths make absence checks inconclusive.
