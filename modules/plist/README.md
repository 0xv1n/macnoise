# plist

Plist creation and modification.

## Modules

### `plist_create`
Creates a plist file using `howett.net/plist`. Cleanup removes file.

### `plist_modify`
Writes a user defaults key via `defaults write`. Maps to T1543. Cleanup restores the prior typed value, including arrays and dictionaries, or removes a newly-created key without overwriting unrelated current preferences.
