# service

LaunchAgent/Daemon persistence, cron job installation, and shell profile modification.

## Modules

### `svc_launch_agent`
Creates and loads a LaunchAgent plist. Maps to T1543.001. Cleanup unloads and removes.

### `svc_launch_daemon`
Creates and loads a LaunchDaemon plist (root required). Maps to T1543.004. Cleanup unloads and removes.

### `svc_cron`
Lists the current crontab, then appends a clearly-marked entry (`# macnoise`). Emits `cron_job_list` and `cron_job_create` events. Maps to T1053.003. Cleanup filters the added entry back out of the crontab.

```bash
macnoise run svc_cron
macnoise run svc_cron --param schedule="@hourly" --param command="/usr/bin/true"
```

### `svc_shell_profile`
Appends a marker block (`# macnoise-marker-start` / `# macnoise-marker-end`) containing a configurable payload to a shell profile file. Defaults to `~/.zshrc` with `export MACNOISE_PERSIST=1`. Emits a `shell_profile_modify` event. Maps to T1546.004. Cleanup strips the marker block from the file.

```bash
macnoise run svc_shell_profile
macnoise run svc_shell_profile --param target=~/.bash_profile --param payload="alias sudo='sudo -E'"
```
