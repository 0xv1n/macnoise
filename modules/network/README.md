# network

Outbound connections, DNS, beaconing, listeners, reverse shells, and data exfiltration simulation.

## Modules

### `net_connect`
Initiates a TCP connection and HTTP GET. Maps to T1071.001.

```bash
macnoise run net_connect --param target=10.0.0.1 --param port=443
```

### `net_listen`
Opens a local listener and simulates an inbound self-connection. Maps to T1571.

### `net_beacon`
Periodic HTTP requests simulating C2 beaconing. Maps to T1071.001, T1102.

```bash
macnoise run net_beacon --param target=http://example.com --param count=5 --param interval=2
```

### `net_dns`
DNS resolution of configurable domains. Maps to T1071.004.

### `net_revshell`
Connects a shell to a remote listener (connection refused is expected without one). Maps to T1059.004.

### `net_exfil`
Sends an HTTP POST with a randomly-generated dummy payload to a target URL. Records request size, response status, and elapsed time. Connection refused is valid telemetry — no listener required. Maps to T1041.

```bash
macnoise run net_exfil
macnoise run net_exfil --param target=http://10.0.0.1:9999/upload --param payload_size=8192
```
