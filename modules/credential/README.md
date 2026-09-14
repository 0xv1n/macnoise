# credential

Native credential-store access that reports the observed command result without treating missing stores or tool failures as permission denials.

## Modules

### `cred_keychain`

Runs `security list-keychains`, resolves the configured user default with a bounded search-list fallback, then attempts to unlock and dump that concrete keychain. An absent keychain is `indeterminate`, a recognized authentication refusal is `denied`, and an unexpected `security` failure is a MacNoise error. Keychain access control is not a TCC permission, so the module requires no TCC privilege in the catalog. Maps to T1555.001.

```bash
macnoise run cred_keychain
macnoise run cred_keychain --param keychain_path=/Users/victim/Library/Keychains/login.keychain-db
```
