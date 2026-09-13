# file

Bounded file discovery, literal file operations, credential access, archiving, hiding, and decoy encryption.

## Modules

### `file_create`
Creates up to 100 files in a literal directory and publishes their concrete paths. `filename` and `content` create one exact, named file. Existing files are never overwritten. Maps to T1074.001. Cleanup removes only unchanged files created by that invocation.

### `file_modify`
Appends to one literal path and publishes it. Maps to T1565.001. Cleanup restores the original only if no later writer changed or replaced the file; otherwise it reports a conflict and preserves the later state.

### `file_find`
Finds up to 100 regular files beneath literal roots without following symbolic links. Exact names, extensions, depth, result count, and file size can be bounded. Publishes the concrete paths for later scenario steps. Maps to T1083.

```bash
macnoise run file_find --param roots=/Users/dev/Documents --param extensions=.txt,.docx
```

### `file_read`
Opens and reads up to 100 literal regular-file paths with contents discarded, then publishes the paths read successfully. Missing paths are indeterminate and permission refusals are denied. Maps to T1005.

```bash
macnoise run file_read --param paths=/tmp/one.txt,/tmp/two.txt
```

### `file_copy`
Copies up to 100 literal regular-file paths into one 0700 staging directory and publishes the copied paths and directory. Copies use 0600 mode, duplicate basenames are rejected, and existing destinations are never overwritten. Cleanup removes only unchanged copies and empty directories created by that invocation. Maps to T1005 and T1074.001.

```bash
macnoise run file_copy --param source_paths=/tmp/one.txt,/tmp/two.txt --param destination_dir=/tmp/macnoise_stage
```

Reusable recipes under `configs/scenarios/recipes/` provide bounded document, browser, credential-file, and keychain target sets. `file_flow.yaml` connects discovery, read, copy, create, modify, and archive operations through typed paths.

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

Copies are written 0600 into a 0700 directory. Cleanup removes only unchanged staged copies and empty directories created by that invocation; `--no-cleanup` keeps them and says so. Maps to T1555.001 and T1074.001.

```bash
macnoise run file_keychain_copy
macnoise run file_keychain_copy --param stage_dir=/var/tmp/macnoise_kc
```

### `file_archive`
Archives one existing literal file or directory using `zip` (default), `ditto`, or `tar`, and publishes the archive path. The source is never created, changed, or removed. Existing output paths are rejected. Cleanup removes only the unchanged archive and empty parent directories created by that invocation. Maps to T1560.001. Requires the chosen tool in `PATH`.

```bash
macnoise run file_archive --param source_path=/tmp/stage
macnoise run file_archive --param source_path=/tmp/stage --param tool=ditto --param output_path=/tmp/staged.zip
```

### `file_encrypt`
Stages at most 100 plaintext decoys with randomized common file extensions, then encrypts each in place with AES-256-GCM (nonce prepended). Existing files are never overwritten. Maps to T1486. Cleanup removes only unchanged decoys and empty directories created by that invocation. The ransomware scenario composes this with a named `file_create` step to drop its ransom note.

```bash
macnoise run file_encrypt
macnoise run file_encrypt --param file_count=20 --param extension=.crypted
```

### `file_hide`
Creates a test file and hides it via `chflags hidden` (Finder-invisible), then creates a dotfile. Existing targets are never overwritten. Emits `file_hide_chflags` and `file_hide_dotfile` events. Maps to T1564.001. Cleanup removes only unchanged files and empty directories created by that invocation.

```bash
macnoise run file_hide
macnoise run file_hide --param work_dir=/var/tmp/macnoise_hide
```
