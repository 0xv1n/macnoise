# process

Process spawning, signal delivery, dylib injection, system discovery, Gatekeeper bypass, and AppleScript/JXA execution.

## Modules

### `proc_spawn`
Spawns a shell command chain. Maps to T1059.004.

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

### `proc_discovery`
Runs a configurable set of macOS reconnaissance commands (`sw_vers`, `system_profiler`, `sysctl`, `ifconfig`, `whoami`, `dscl`, `csrutil status`, `fdesetup status`), plus security software enumeration via `systemextensionsctl list`, the application firewall state, and a process scan for known endpoint agents. Each command emits a separate `system_discovery` event with structured output. Maps to T1082, T1016, T1033, T1518, T1518.001.

`systemextensionsctl list` carries most of the security-software signal on modern macOS, since every current EDR registers an Endpoint Security system extension and it needs no vendor list to stay current. The agent process scan names specific vendors and is illustrative rather than exhaustive - a miss costs one match, while the exec that a detection actually sees still happens.

The security commands are part of the defaults on purpose. A technique claimed in `Info()` but only reachable by overriding `commands` would be unbacked on a default run, which is the defect the original T1518 claim had, and `discovery_test.go` fails if a claim loses its backing command.

```bash
macnoise run proc_discovery
macnoise run proc_discovery --param commands="sw_vers,whoami,csrutil status"
```

```bash
macnoise run proc_discovery
macnoise run proc_discovery --param commands="sw_vers,whoami,csrutil status"
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
