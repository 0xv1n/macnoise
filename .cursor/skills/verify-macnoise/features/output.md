# Output and audit

Users save machine-readable events and audit records for later analysis.

## Sub-features
- JSONL events through `--format` and `--output`; audit records through `--audit-log`.

## How to get to it (user POV)
- Add output flags to a module run or scenario.

## Driving it with the CLI
Preconditions: controlled loopback listener as in `run.md`; unique, initially absent evidence files.
- Run `"$RUN/macnoise" run net_connect --param target=127.0.0.1 --param port="$PORT" --format jsonl --output "$EVIDENCE/events.jsonl" --audit-log "$EVIDENCE/audit.jsonl" --run-id verify-output`. Capture stdout, stderr, and exit code. Parse each nonempty line as JSON and check the event outcome is `executed`, stderr contains `run_id=verify-output`, audit `metadata.correlation_uid` is `verify-output`, and the listener observed the connection.

## Gotchas
- Output and audit files append. Never reuse a prior run's files; a valid JSON file alone does not prove the action occurred.
