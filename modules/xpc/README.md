# xpc

XPC service enumeration.

## Modules

### `xpc_enumerate`
Enumerates launchd service registrations via `launchctl print`, which is where macOS XPC services are registered. Always enumerates the current user's GUI domain (`gui/<uid>`), and the `system` domain (readable unprivileged), emitting one `xpc_enumerate` event per domain with the service labels found. Maps to T1007 and T1057.

```bash
macnoise run xpc_enumerate
macnoise run xpc_enumerate --param filter=com.apple.security --param max_results=20
```

The module reads launchd state and does not open XPC connections. It was previously named `xpc_connect`, which claimed a connection it never made.
