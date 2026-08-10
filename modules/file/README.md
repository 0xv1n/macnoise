# file

File creation, modification, browser credential probing, archiving, and hiding.

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
