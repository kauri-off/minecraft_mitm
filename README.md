# minecraft_mitm

A Minecraft man-in-the-middle proxy written in Rust. Sits between a Minecraft client and server, forwarding traffic transparently while allowing you to inspect and log packets in real time — or dump them to a JSON file for offline analysis.

## Features

- Transparent TCP proxy for Minecraft (protocol 774 / 1.21.11)
- Intercepts the handshake and rewrites the server address before forwarding
- Handles the login sequence, including compression negotiation
- Logs clientbound and/or serverbound packets with packet ID, length, and raw payload
- Dumps packets to a JSON file (`--dump-json <path>`) for offline analysis
- Responds to status pings with a custom MOTD so the proxy itself looks like a server to the client

## Limitations

- Online-mode / encryption is **not** supported. The target server must be in offline mode (or behind a proxy/plugin that bypasses auth).
- Transfer intent (intent `3`) is not yet implemented.

## Installation

```bash
git clone https://github.com/kauri-off/minecraft_mitm.git
cd minecraft_mitm
cargo build --release
```

The compiled binary will be at `target/release/minecraft_mitm`.

## Usage

```
minecraft_mitm [OPTIONS] --bind <BIND> --connect-addr <CONNECT_ADDR> \
               --handshake-ip <HANDSHAKE_IP> --handshake-port <HANDSHAKE_PORT>
```

### Options

| Flag                          | Description                                                  |
| ----------------------------- | ------------------------------------------------------------ |
| `--bind <addr:port>`          | Address the proxy listens on (e.g. `0.0.0.0:25565`)          |
| `--connect-addr <addr:port>`  | Backend server to forward connections to                     |
| `--handshake-ip <ip>`         | Server address written into the forwarded handshake packet   |
| `-p, --handshake-port <port>` | Server port written into the forwarded handshake packet      |
| `--cb`                        | Log clientbound packets to stdout                            |
| `--sb`                        | Log serverbound packets to stdout                            |
| `--dump-json <path>`          | Append all packets to a JSON file (one JSON object per line) |

### Example

```bash
# Proxy localhost:25565 → my-server.example.com:25565
# Log all clientbound packets and dump everything to packets.json
minecraft_mitm \
  --bind 0.0.0.0:25565 \
  --connect-addr my-server.example.com:25565 \
  --handshake-ip my-server.example.com \
  --handshake-port 25565 \
  --cb \
  --dump-json packets.json
```

Point your Minecraft client at `localhost:25565`. The proxy will forward the session to `my-server.example.com:25565` and write every packet to `packets.json`.

### JSON dump format

Each line in the output file is a self-contained JSON object:

```json
{
  "direction": "ClientBound",
  "packet_id": 38,
  "length": 12,
  "payload": [0, 1, 2, 3],
  "timestamp": "2024-11-01T12:00:00.123Z"
}
```

| Field       | Type   | Description                        |
| ----------- | ------ | ---------------------------------- |
| `direction` | string | `"ClientBound"` or `"ServerBound"` |
| `packet_id` | number | Numeric packet ID                  |
| `length`    | number | Payload length in bytes            |
| `payload`   | array  | Raw payload bytes                  |
| `timestamp` | string | ISO 8601 UTC timestamp             |

## License

MIT — see [LICENSE](LICENSE) for details.
