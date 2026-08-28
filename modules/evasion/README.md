# evasion

Defense evasion and anti-forensics: log clearing, timestamp manipulation, and history removal.

## Modules

### `evade_log_clear`
Timestomps a staging file via `os.Chtimes`, attempts `log erase --all` (fails without root - the denied exec is the signal), and creates then removes a mock `.zsh_history`. Maps to T1070.006, T1070.002, T1070.003.

All artifacts live in a staging directory (default `/tmp/macnoise_evasion`) and are removed on cleanup. The user's real shell history is never touched.

```bash
macnoise run evade_log_clear
macnoise run evade_log_clear --param stage_dir=/var/tmp/macnoise_evasion
```
