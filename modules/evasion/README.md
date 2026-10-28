# evasion

Defense evasion and anti-forensics: log clearing, timestamp manipulation, and history removal.

## Modules

### `evade_log_clear`
Timestomps a staging file via `os.Chtimes`, runs `log erase --all`, and removes real shell history files. With sufficient privileges, the log command erases the real macOS unified logs. By default, history removal targets the current user's `.zsh_history` and `.bash_history`. Maps to T1070.006, T1070.002, T1070.003.

The `history_paths` parameter replaces the default history targets. Cleanup removes the MacNoise-owned timestomp artifact but does not restore erased logs or history files.

```bash
macnoise run evade_log_clear
macnoise run evade_log_clear \
  --param history_paths=/Users/test/.zsh_history \
  --param history_paths=/Users/test/.custom_history
```

### `evade_masquerade`
Copies a benign system utility (default `/usr/bin/true`) into a staging directory under a name that impersonates a legitimate macOS process (default `com.apple.WindowServer`), then executes it. The exec fires for a process whose name and location masquerade as a trusted system component while its real provenance differs. Maps to T1036.003, T1036.005.

The staged binary lives in the staging directory (default `/tmp/macnoise_masquerade`). MacNoise refuses to replace an existing destination. Cleanup removes only the unchanged binary and directories created by that invocation.

```bash
macnoise run evade_masquerade
macnoise run evade_masquerade --param masquerade_name=mdworker_shared --param source_binary=/bin/cp
```
