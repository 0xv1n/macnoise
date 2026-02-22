# process

Process spawning, signal delivery, dylib injection, system discovery, Gatekeeper bypass, and AppleScript/JXA execution.

## Modules

### `proc_spawn`
Spawns a shell command chain. Maps to T1059.004.

### `proc_signal`
Forks a process and sends SIGSTOP/SIGCONT/SIGTERM. Maps to T1106. Requires macOS (darwin).

### `proc_inject`
Spawns a process with `DYLD_INSERT_LIBRARIES` set. Maps to T1574.006.

### `proc_discovery`
Runs a configurable set of macOS reconnaissance commands (`sw_vers`, `system_profiler`, `sysctl`, `ifconfig`, `whoami`, `dscl`, `csrutil status`, `fdesetup status`). Each command emits a separate `system_discovery` event with structured output. Maps to T1082, T1016, T1033, T1518.

```bash
macnoise run proc_discovery
macnoise run proc_discovery --param commands="sw_vers,whoami,csrutil status"
```

### `proc_gatekeeper`
Sets and removes the `com.apple.quarantine` xattr on a test file, then queries `spctl --status`. Emits `xattr_quarantine_remove` and `spctl_status_check` events. Maps to T1553.001. Cleanup removes the test file.

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
