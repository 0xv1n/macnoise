# process

Exact process execution, signal delivery, dylib injection, Gatekeeper bypass, and AppleScript/JXA execution.

## Modules

### `proc_exec`
Executes one executable with an exact argument list and no implicit shell. It publishes the combined output and exit code for scenario dataflow. `working_dir` sets the child process directory, including an observed mounted-volume path. Set `accept_nonzero=true` when a completed non-zero exit is valid telemetry rather than a MacNoise error.

```bash
macnoise run proc_exec --param executable=/usr/bin/id --param args=-un
macnoise scenario configs/scenarios/discovery.yaml
macnoise scenario configs/scenarios/process_chain.yaml
```

### `proc_signal`
Forks a process and sends SIGSTOP/SIGCONT/SIGTERM. Maps to T1106. Requires macOS (darwin).

### `proc_inject`
Spawns a process with `DYLD_INSERT_LIBRARIES` set and reports whether dyld actually acted on it, as `outcome: honored | stripped | indeterminate`. Maps to T1574.006.

The default target is macnoise's own binary rather than a system binary. On a host with SIP enabled, which is any real endpoint, system binaries under `/usr/bin` and `/bin` have the variable dropped before the process starts, so no injection occurs; that holds even for a copy with its signature removed or re-signed ad-hoc, so no usable target can be derived from them. With SIP disabled they are injectable, which is why some CI images behave differently. macnoise is built locally and only ad-hoc signed, so dyld honours the variable either way.

The dylib does not need to exist. dyld aborts the process when it cannot load an inserted library, and that refusal is both the evidence the variable survived and a loud, observable event. Pass `--param target=` to point at your own unsigned binary instead.

```bash
macnoise run proc_inject
macnoise run proc_inject --param target=/tmp/my_unsigned_binary --param dylib_path=/tmp/evil.dylib
```

### `proc_gatekeeper`
Sets and removes the `com.apple.quarantine` xattr on a test file, then queries `spctl --status`. Emits `xattr_quarantine_set`, `xattr_quarantine_remove`, and `spctl_status_check` events. Maps to T1553.001. Cleanup removes the test file.

```bash
macnoise run proc_gatekeeper
macnoise run proc_gatekeeper --param target_path=/tmp/test_gk
```

### `proc_osascript` *(darwin only)*
Executes configurable AppleScript or JXA (JavaScript for Automation) via `osascript -l`. Defaults to a benign `display notification`. Maps to T1059.002, T1059.007.

```bash
macnoise run proc_osascript
macnoise run proc_osascript --param language=JavaScript --param script="Application('Finder').activate()"
```
