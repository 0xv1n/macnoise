# tcc

TCC permission probes covering Full Disk Access, Contacts, and Keychain.

## Modules

### `tcc_fda`
Attempts to open the per-user `TCC.db` (`~/Library/Application Support/com.apple.TCC/TCC.db`). That file is owned by the user running the probe, so POSIX permits the read and only Full Disk Access decides the outcome; the system database under `/Library` is root-owned and would be refused by mode bits before TCC is ever consulted. Override with `--param tcc_path=<path>`. Maps to T1555.

### `tcc_contacts`
Enumerates the AddressBook directory. Maps to T1636.003.

Both probes report `result` as one of `granted`, `denied`, `absent`, or `error`. `absent` means the resource does not exist, so no TCC decision was made, and it is deliberately distinct from `denied` so that consumers counting denials do not treat an unused feature as a privacy refusal.

### `tcc_keychain`
Probes keychain access by running `security list-keychains`, `security unlock-keychain`, and `security dump-keychain`. An empty password causes an expected denial — generating denied-access telemetry without needing valid credentials. Emits `keychain_list`, `keychain_unlock_attempt`, and `keychain_dump_attempt` events. Maps to T1555.001.

```bash
macnoise run tcc_keychain
macnoise run tcc_keychain --param keychain_path=/Users/victim/Library/Keychains/login.keychain-db
```
