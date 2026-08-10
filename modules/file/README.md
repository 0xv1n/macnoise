# file

File creation, modification, credential and keychain reads, archiving, and hiding.

## Modules

### `file_create`
Creates files in a directory. Maps to T1074.001. Cleanup removes created files.

### `file_modify`
Appends to a file. Maps to T1565.001. Cleanup restores original content.

### `file_browser_creds`
Opens and reads known browser credential files, discarding the contents (no copy, nothing retained). Covers the Chromium family (Chrome, Chrome Canary, Brave, Arc, Edge, Vivaldi, Yandex, Opera, OperaGX) across every profile directory, reading `Login Data`, `Cookies` (both the legacy and `Network/` locations), `Web Data`, and the `Local State` key that decrypts them; Firefox (`logins.json`, `key4.db`, `cookies.sqlite` per profile); and Safari. Emits `browser_cred_read` per file opened, carrying bytes read or the denial reason, and `browser_cred_probe` for paths that are not present. Maps to T1555.003.

```bash
macnoise run file_browser_creds
macnoise run file_browser_creds --param browsers=chrome,firefox
```

### `file_cred_files`
Opens and reads well-known non-browser credential files, discarding the contents. Covers SSH private keys (`~/.ssh/id_*`, public `.pub` keys skipped since they are not secrets), `~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, and `~/.env`. The `paths` param adds extra targets, e.g. a project `.env`. Emits `cred_file_read` per file opened, carrying bytes read (executed) or the denial reason (denied), and `cred_file_probe` for paths that are not present (indeterminate). Maps to T1552.001. The read, not a stat, is deliberate: an unreadable file that `stat` would report as present is a real access denial, and the module records it as one.

```bash
macnoise run file_cred_files
macnoise run file_cred_files --param paths=/Users/dev/project/.env
```

### `file_keychain_copy`
Copies the macOS keychain databases wholesale into a staging directory, the step AMOS performs before archiving and exfiltrating them. Targets the legacy `~/Library/Keychains/login.keychain-db`, the data-protection keychain under the per-user UUID directory (`~/Library/Keychains/<uuid>/keychain-2.db`, globbed since the UUID varies), `/Library/Keychains/System.keychain`, and the root-owned `/Library/Keychains/system-keychain-2.db`. Emits `keychain_read` and `keychain_copy` per store: a copy is a read of the source plus a create of the destination, and OCSF has no single activity covering both. A store that is absent is `indeterminate` (a GUI login creates `login.keychain-db`, so an ssh-only account has none), one that cannot be opened is `denied` (expected for the system data-protection keychain without root), and a failure to write the copy is `error` rather than either.

Copies are written 0600 into a 0700 directory, deliberately tighter than the 0644/0755 the other file modules use: the staged file is a real credential store, and the conventional mode would leave it more exposed in `/tmp` than the original. Cleanup removes the staging directory; `--no-cleanup` keeps it and says so. Maps to T1555.001 and T1074.001.

```bash
macnoise run file_keychain_copy
macnoise run file_keychain_copy --param stage_dir=/var/tmp/macnoise_kc
```

### `file_archive`
Creates a staging directory with three test files, then archives them using `zip` (default), `ditto`, or `tar`. Emits an `archive_create` event with path and size. Maps to T1560.001. Cleanup removes both the archive and staging directory. Requires the chosen tool in `PATH`.

```bash
macnoise run file_archive
macnoise run file_archive --param tool=ditto --param output_path=/tmp/staged.zip
```

### `file_hide`
Creates a test file and hides it via `chflags hidden` (Finder-invisible), then creates a dotfile. Emits `file_hide_chflags` and `file_hide_dotfile` events. Maps to T1564.001. Cleanup removes the working directory.

```bash
macnoise run file_hide
macnoise run file_hide --param work_dir=/var/tmp/macnoise_hide
```
