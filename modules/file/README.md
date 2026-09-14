# file

Bounded file discovery, literal file operations, archiving, hiding, and decoy encryption.

## Modules

### `file_create`
Creates up to 100 files in a literal directory and publishes their concrete paths. `filename` and `content` create one exact, named file; `executable=true` uses mode 0755 for mounted-execution recipes. Existing files are never overwritten. Maps to T1074.001. Cleanup removes only unchanged files created by that invocation.

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

Reusable recipes under `configs/scenarios/recipes/` provide bounded document, browser, credential-file, and keychain target sets beneath explicit roots. Scenarios connect those target lists to `file_read` or `file_copy`; `file_flow.yaml` connects discovery, read, copy, create, modify, and archive operations through typed paths.

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
