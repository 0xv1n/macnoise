# tcc

TCC permission probes covering Full Disk Access, Contacts, and Keychain.

## Modules

### `tcc_fda`
Attempts to open TCC.db. Reports grant/deny. Maps to T1555.

### `tcc_contacts`
Enumerates AddressBook directory. Maps to T1636.003.

### `tcc_keychain`
Probes keychain access by running `security list-keychains`, `security unlock-keychain`, and `security dump-keychain`. An empty password causes an expected denial — generating denied-access telemetry without needing valid credentials. Emits `keychain_list`, `keychain_unlock_attempt`, and `keychain_dump_attempt` events. Maps to T1555.001.

```bash
macnoise run tcc_keychain
macnoise run tcc_keychain --param keychain_path=/Users/victim/Library/Keychains/login.keychain-db
```
