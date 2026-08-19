# endpoint_security

Endpoint Security framework event triggers.

## Modules

### `es_file`
Walks a file through its full lifecycle - create, open and read, write, chmod, rename, delete - triggering ES_EVENT_TYPE_NOTIFY_CREATE/OPEN/WRITE/SETMODE/RENAME/UNLINK in that order. Maps to T1074.001.

The order is load-bearing: chmod and rename have to happen while the file exists, and the rename has to precede the unlink that removes it under its new name. `NOTIFY_OPEN` also fires incidentally from the credential modules, but this is the module an operator runs to exercise ES file coverage, so it names the event rather than leaving it implicit.

```bash
macnoise run es_file
macnoise run es_file --param work_dir=/var/tmp/es_test
```

### `es_process`
Executes nested process chain (triggers ES_EVENT_TYPE_NOTIFY_EXEC/FORK/EXIT). Maps to T1059.004.

### `es_mount`
Builds a disk image, mounts it, executes a payload from the mounted volume, then unmounts (triggers ES_EVENT_TYPE_NOTIFY_MOUNT/EXEC/UNMOUNT). Maps to T1204.002.

Emulates the `.dmg` delivery vector the AMOS scenario lists as upstream of itself. The execution step is the point: a bare mount is weak signal, while a process launched from a `/Volumes` path is what fake-installer delivery looks like on a real endpoint. The mount point is read back from `hdiutil` rather than assumed, since macOS appends a suffix when a volume of the same name is already mounted.
