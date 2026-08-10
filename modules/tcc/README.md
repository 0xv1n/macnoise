# tcc

TCC permission probes covering Full Disk Access, Contacts, Keychain, Accessibility, and Screen Recording.

## Modules

### `tcc_fda`
Attempts to open the per-user `TCC.db` (`~/Library/Application Support/com.apple.TCC/TCC.db`). That file is owned by the user running the probe, so POSIX permits the read and only Full Disk Access decides the outcome; the system database under `/Library` is root-owned and would be refused by mode bits before TCC is ever consulted. Override with `--param tcc_path=<path>`. Maps to T1555.

### `tcc_contacts`
Enumerates the AddressBook directory. Maps to T1636.003.

Both probes report `result` as one of `granted`, `denied`, `absent`, or `error`. `absent` means the resource does not exist, so no TCC decision was made, and it is deliberately distinct from `denied` so that consumers counting denials do not treat an unused feature as a privacy refusal.

### `tcc_keychain`
Probes keychain access by running `security list-keychains`, `security unlock-keychain`, and `security dump-keychain`. An empty password causes an expected denial — generating denied-access telemetry without needing valid credentials. Emits `keychain_list`, `keychain_unlock_attempt`, and `keychain_dump_attempt` events. Maps to T1555.001.

```bash
macnoise run tcc_keychain
macnoise run tcc_keychain --param keychain_path=/Users/victim/Library/Keychains/login.keychain-db
```

### `tcc_accessibility`
Reads UI elements through System Events via `osascript`, which requires the Accessibility permission. Returns data when granted, a specific authorization error (`-1719` / assistive access) when not. Emits `tcc_accessibility_probe` with `result` as `executed` (granted), `denied` (refused), or `indeterminate` (no GUI session to run System Events). Maps to T1056.001 — Accessibility is the permission that enables reading UI/secure-field contents as they are typed, a keylogging vector.

### `tcc_screen_recording`
Runs `screencapture` to a temp file, records the byte count, and deletes the file — the contents are never read or emitted. Emits `screen_capture_attempt`. Maps to T1113.

Unlike the other TCC probes this is **not** a granted/denied classifier: command-line `screencapture` exits 0 and writes a valid image whether or not Screen Recording is granted (the desktop is always capturable, other apps' windows are silently excluded), and no CLI signal reveals the grant. Determining it would need `CGPreflightScreenCaptureAccess` via cgo, which this pure-Go tool avoids. So the module honestly reports only `executed` (the capture ran — itself the telemetry a detection keys on) or `indeterminate` (no display/GUI to attempt it), with `permission: indeterminate` in the details. It never fabricates a verdict it cannot determine.

Both modules need a GUI (Aqua) session; over ssh or on a headless runner they report `indeterminate` rather than failing.
