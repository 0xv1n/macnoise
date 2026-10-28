# Run a module

Users run an explicit module with parameters to generate telemetry.

## Sub-features
- Connect to a controlled local TCP listener.

## How to get to it (user POV)
- `run net_connect --param target=127.0.0.1 --param port=<port>`.

## Driving it with the CLI
Preconditions: Python 3. Remove any previous `$RUN/listener.log`, then start a one-shot listener owned by this run with `python3 -u -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); s.settimeout(30); print(s.getsockname()[1],flush=True); c,a=s.accept(); print("accepted",a,flush=True); c.close(); s.close()' > "$RUN/listener.log" 2>&1 & LISTENER=$!`. Wait for the first line of the log, then set `PORT=$(head -n 1 "$RUN/listener.log")`.
- Run `"$RUN/macnoise" run net_connect --param target=127.0.0.1 --param port="$PORT"` and capture output and exit code. Wait for `"$LISTENER"`, then check `"$RUN/listener.log"` for `accepted` and the CLI event for a successful connection. If the drive fails, stop and wait for this PID only.

## Gotchas
- A refused connection is not proof of a successful connection. Never target an external host without explicit authorization.
