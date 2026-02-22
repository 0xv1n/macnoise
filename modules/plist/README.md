# plist

Plist creation and modification.

## Modules

### `plist_create`
Creates a plist file using `howett.net/plist`. Cleanup removes file.

### `plist_modify`
Writes a user defaults key via `defaults write`. Maps to T1543. Cleanup runs `defaults delete`.
