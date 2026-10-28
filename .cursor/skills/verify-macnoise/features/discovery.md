# Discovery

Users browse modules and inspect their parameters before running them.

## Sub-features
- List all modules or filter by category; inspect categories and module details.

## How to get to it (user POV)
- `list`, `list --category network`, `categories`, and `info net_connect`.

## Driving it with the CLI
Preconditions: built binary and doctor pass.
- Run `"$RUN/macnoise" list`, `"$RUN/macnoise" list --category network`, `"$RUN/macnoise" categories`, and `"$RUN/macnoise" info net_connect`. Capture each exit code and output. The network list contains `net_connect`; info names its target and port parameters; categories includes network.

## Gotchas
- The catalog can change; use the checkout's actual output as evidence, not a fixed module count.
