# file

File creation, modification, browser credential probing, archiving, and hiding.

## Modules

### `file_create`
Creates files in a directory. Maps to T1074.001. Cleanup removes created files.

### `file_modify`
Appends to a file. Maps to T1565.001. Cleanup restores original content.

### `file_browser_creds`
Probes known browser credential file paths via `os.Stat` (no read, no copy). Covers Chrome, Brave, Edge, Arc, Vivaldi, Opera, OperaGX, Firefox, and Safari. Emits one `browser_cred_probe` event per path indicating existence, size, and last-modified time. Maps to T1555.003.

```bash
macnoise run file_browser_creds
macnoise run file_browser_creds --param browsers=chrome,firefox
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
