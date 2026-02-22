# endpoint_security

Endpoint Security framework event triggers.

## Modules

### `es_file`
Creates, writes, and deletes a file (triggers ES_EVENT_TYPE_NOTIFY_CREATE/WRITE/UNLINK). Maps to T1074.001.

### `es_process`
Executes nested process chain (triggers ES_EVENT_TYPE_NOTIFY_EXEC/FORK/EXIT). Maps to T1059.004.
