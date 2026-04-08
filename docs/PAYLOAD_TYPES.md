# MeshCore Payload Types & Size Restrictions

## Packet Framing

```
[Header(1)] [PathLen(1)] [Path(0-64)] [Payload(0-184)]
```

| Constant         | Value     | Source              |
|------------------|-----------|---------------------|
| MaxPacketPayload | 184 bytes | codec/packet.go     |
| MaxPathSize      | 64 bytes  | codec/packet.go     |
| CipherBlockSize  | 16 bytes  | crypto/cipher.go    |
| CipherMACSize    | 2 bytes   | crypto/cipher.go    |

RS232 serial bridge adds its own framing: `[Magic(2: 0xC03E)] [Length(2)] [Data(0-256)] [Checksum(2: Fletcher16)]`

---

## Payload Types

All payload types are 4-bit values stored in the packet header.

| Code | Name         | Description                                      |
|------|--------------|--------------------------------------------------|
| 0x00 | REQ          | Authenticated request (login, stats, telemetry)  |
| 0x01 | RESPONSE     | Reply to REQ or ANON_REQ                         |
| 0x02 | TXT_MSG      | Text message (Plain, CLI, or Signed subtypes)    |
| 0x03 | ACK          | 4-byte checksum acknowledgment                   |
| 0x04 | ADVERT       | Node advertisement (identity + optional metadata)|
| 0x05 | GRP_TXT      | Group/channel text message (unencrypted)         |
| 0x06 | GRP_DATA     | Group/channel datagram (unencrypted)             |
| 0x07 | ANON_REQ     | Anonymous request (login without prior contact)  |
| 0x08 | PATH         | Reversed flood path with optional bundled payload|
| 0x09 | TRACE        | Per-hop SNR trace for debugging/discovery        |
| 0x0A | MULTIPART    | Fragmented packet container                      |
| 0x0B | CONTROL      | Discovery request/response                       |
| 0x0F | RAW_CUSTOM   | Application-defined raw bytes                    |

---

## Encryption Overhead

All addressed payloads (TXT_MSG, REQ, RESPONSE, ANON_REQ) use AES-128 ECB with a truncated HMAC-SHA256:

- **MAC:** 2 bytes prepended to ciphertext
- **Padding:** plaintext padded to next 16-byte block boundary (up to 15 bytes overhead)

---

## Per-Type Details

### TXT_MSG (0x02)

The most common payload type. Addressed to a specific recipient.

**Wire layout:**
```
[DestHash(1)] [SrcHash(1)] [MAC(2)] [Ciphertext...]
```

**Decrypted content:**
```
[Timestamp(4)] [TypeAttempt(1)] [SenderPrefix(4, signed only)] [MessageText(0-160)]
```

**Subtypes** (upper 6 bits of TypeAttempt):
| Value | Name         | Use                          |
|-------|--------------|------------------------------|
| 0x00  | TxtTypePlain | Standard direct messages     |
| 0x01  | TxtTypeCLI   | CLI commands to room servers |
| 0x02  | TxtTypeSigned| Signed with 4-byte pubkey prefix |

**Attempt counter:** lower 2 bits (0-3), tracks retransmissions.

**Maximum text length: 160 bytes** (`MaxTextLen = 10 * CipherBlockSize`)

**Overhead breakdown:**
```
184  max payload
 -4  addressed header (dest_hash + src_hash + MAC)
 -2  encryption MAC
 -5  txt header (timestamp + type/attempt)
-13  worst-case AES padding
───
160  max message text
```

### ACK (0x03)

**Fixed size: 4 bytes** — a uint32 LE checksum of `timestamp + text + sender_pubkey`.

The checksum matches firmware's `strlen()` behavior: only counts plaintext up to the first null byte (AES padding excluded).

### ADVERT (0x04)

**Minimum size: 100 bytes** (fixed fields only)

```
[PubKey(32)] [Timestamp(4)] [Signature(64)] [AppData(variable)]
```

**AppData structure** (all optional, presence indicated by flags byte):

```
[Flags(1)] [Location(8)?] [Feature1(2)?] [Feature2(2)?] [Name(null-terminated)?]
```

| Flag Bit | Mask | Field      | Size    |
|----------|------|------------|---------|
| 4        | 0x10 | Location   | 8 bytes (lat + lon as int32) |
| 5        | 0x20 | Feature1   | 2 bytes |
| 6        | 0x40 | Feature2   | 2 bytes |
| 7        | 0x80 | Name       | variable, null-terminated |

**Node types** (lower 4 bits of flags):
| Value | Type     |
|-------|----------|
| 0x01  | Chat     |
| 0x02  | Repeater |
| 0x03  | Room     |
| 0x04  | Sensor   |

Typical ADVERT with name and location: ~110-130 bytes.

### REQ (0x00)

**Header:** 4 bytes (addressed)

**Decrypted content:**
```
[Timestamp(4)] [RequestType(1)] [RequestData(variable)]
```

| Type | Name              | Extra Data                |
|------|-------------------|---------------------------|
| 0x00 | ReqTypeLogin      | —                         |
| 0x01 | ReqTypeGetStats   | —                         |
| 0x02 | ReqTypeKeepalive  | SyncSince(4)              |
| 0x03 | ReqTypeGetTelemetry | —                       |
| 0x04 | ReqTypeGetMinMaxAvg | —                       |
| 0x05 | ReqTypeGetAccessList | —                      |
| 0x06 | ReqTypeGetNeighbors | —                       |
| 0x07 | ReqTypeGetOwnerInfo | —                       |

### RESPONSE (0x01)

**Header:** 4 bytes (addressed)

**Decrypted content:**
```
[Tag(4)] [ResponseContent(variable)]
```

### ANON_REQ (0x07)

Used for initial login without prior key exchange.

**Header: 35 bytes**
```
[DestHash(1)] [EphemeralPubKey(32)] [MAC(2)]
```

### GRP_TXT (0x05) & GRP_DATA (0x06)

**Header: 3 bytes**
```
[ChannelHash(1)] [MAC(2)]
```

Content is encrypted but not authenticated to a specific sender. GRP_TXT follows the same timestamp + type/attempt + message layout as TXT_MSG. GRP_DATA is arbitrary bytes.

**Max group text: ~175 bytes** (184 - 3 header - overhead)

### PATH (0x08)

Carries a reversed flood path back to the sender, optionally bundling an ACK or RESPONSE.

**Decrypted content:**
```
[PathLen(1)] [PathHashes(N)] [ExtraType(1)] [Extra(variable)]
```

### TRACE (0x09)

Per-hop SNR collection for network debugging.

**Fixed header: 9 bytes**
```
[Tag(4)] [AuthCode(4)] [Flags(1)]
```

Hash size per hop is determined by lower 2 bits of flags: `1 << (flags & 0x03)` bytes.

The packet's Path field stores per-hop SNR values (int8, multiply by 0.25 for dB), not relay hashes.

### CONTROL (0x0B)

**Subtypes:**

**DISCOVER_REQ (flags upper nibble = 0x08):**
```
[Flags(1)] [TypeFilter(1)] [Tag(4)] [Since(4)?]
```

**DISCOVER_RESP (flags upper nibble = 0x09):**
```
[Flags(1)] [SNR(1)] [Tag(4)] [PubKey(8 or 32)]
```

### MULTIPART (0x0A)

**Header byte:** upper 4 bits = remaining fragment count, lower 4 bits = inner payload type.

Currently only used for ACK fragmentation in firmware.

### RAW_CUSTOM (0x0F)

No defined structure — application-specific.

---

## Node Type Capabilities

| Node Type      | Sends TXT_MSG | Processes CLI | Forwards Packets | Typical Role     |
|----------------|---------------|---------------|------------------|------------------|
| Chat (0x01)    | Plain only    | No            | No               | Companion/client |
| Repeater (0x02)| No            | No            | Yes              | Relay            |
| Room (0x03)    | Plain + CLI   | Yes           | Yes              | Server           |
| Sensor (0x04)  | Yes           | No            | No               | Telemetry        |

---

## Room Server CLI Commands

CLI commands are sent as TXT_MSG with `TxtTypeCLI` (0x01). Only **admin** clients can send CLI commands; non-admin CLI messages are silently dropped with no ACK.

Commands are processed in two layers: room-server-specific commands in `MyMesh::handleCommand()`, then common commands in `CommonCLI::handleCommand()`.

An optional 3-byte companion prefix (format `XX|`) may precede any command. If present, the prefix is reflected back in the reply. This is used by companion radio CLI interfaces.

Some commands are **serial-only** (`sender_timestamp == 0`), meaning they can only be executed from the local serial console, not over the air.

### Room Server Commands

| Command | Args | Description | Access |
|---------|------|-------------|--------|
| `setperm` | `<pubkey-hex> <perm-int>` | Set client permissions in ACL | Admin |
| `get acl` | — | Dump ACL to serial | Serial only |

### Common CLI Commands

#### System

| Command | Args | Description | Access |
|---------|------|-------------|--------|
| `reboot` | — | Reboot the device | Admin |
| `clkreboot` | — | Reset clock to May 2024 epoch and reboot | Admin |
| `ver` | — | Firmware version and build date | Admin |
| `board` | — | Board manufacturer name | Admin |
| `erase` | — | Format the filesystem | Serial only |
| `start ota` | — | Begin OTA update (if supported) | Admin |

#### Clock

| Command | Args | Description | Access |
|---------|------|-------------|--------|
| `clock` | — | Show current UTC time | Admin |
| `clock sync` | — | Sync clock to sender's timestamp (forward only) | Admin |
| `time` | `<epoch-secs>` | Set clock to epoch seconds (forward only) | Admin |

#### Advertisement

| Command | Args | Description | Access |
|---------|------|-------------|--------|
| `advert` | — | Send a flood advertisement | Admin |

#### Statistics

| Command | Args | Description | Access |
|---------|------|-------------|--------|
| `clear stats` | — | Reset all statistics counters | Admin |
| `stats-core` | — | Core stats (uptime, errors, queue) | Serial only |
| `stats-radio` | — | Radio stats (airtime, SNR, RSSI) | Serial only |
| `stats-packets` | — | Packet stats (sent/recv, flood/direct, dups) | Serial only |

#### Configuration — Get

All prefixed with `get `.

| Key | Description |
|-----|-------------|
| `name` | Node name |
| `role` | Firmware role (e.g. "room_server") |
| `public.key` | Node's public key (hex) |
| `prv.key` | Node's private key (hex) — **serial only** |
| `radio` | Radio params: `freq,bw,sf,cr` |
| `freq` | LoRa frequency |
| `tx` | TX power (dBm) |
| `lat` | Configured latitude |
| `lon` | Configured longitude |
| `repeat` | Packet forwarding: "on" or "off" |
| `af` | Airtime budget factor |
| `rxdelay` | RX delay base |
| `txdelay` | TX delay factor |
| `direct.txdelay` | Direct TX delay factor |
| `flood.max` | Max flood path length |
| `advert.interval` | Local advert interval (minutes) |
| `flood.advert.interval` | Flood advert interval (hours) |
| `guest.password` | Room/guest password |
| `allow.read.only` | Whether read-only guests allowed |
| `multi.acks` | Extra ACK transmit count |
| `int.thresh` | Interference threshold |
| `agc.reset.interval` | AGC reset interval (seconds) |
| `owner.info` | Owner info string (`\|` = newline) |
| `adc.multiplier` | ADC voltage multiplier |
| `bridge.type` | Bridge type: "rs232", "espnow", or "none" |
| `bridge.enabled` | Bridge on/off (if bridge compiled in) |
| `bridge.delay` | Bridge delay in ms |
| `bridge.source` | Bridge packet source: "logTx" or "logRx" |
| `bridge.baud` | RS232 baud rate |
| `bridge.channel` | ESP-NOW channel (1-14) |
| `bridge.secret` | ESP-NOW XOR encryption secret |
| `pwrmgt.support` | Power management supported? |
| `pwrmgt.source` | Power source: "external" or "battery" |
| `pwrmgt.bootreason` | Reset and shutdown reason strings |
| `pwrmgt.bootmv` | Boot voltage (mV) |

#### Configuration — Set

All prefixed with `set `.

| Key | Args | Constraints |
|-----|------|-------------|
| `name` | `<string>` | No `[]/:,?*` characters |
| `password` | `<string>` | Max 15 chars |
| `guest.password` | `<string>` | Max 15 chars |
| `radio` | `<freq> <bw> <sf> <cr>` | freq 300-2500, sf 5-12, cr 5-8, bw 7-500 |
| `freq` | `<float>` | Serial only |
| `tx` | `<int>` | TX power in dBm |
| `lat` | `<float>` | Latitude |
| `lon` | `<float>` | Longitude |
| `repeat` | `on\|off` | Packet forwarding |
| `af` | `<float>` | Airtime factor (0-9) |
| `rxdelay` | `<float>` | RX delay base (>=0) |
| `txdelay` | `<float>` | TX delay factor (>=0) |
| `direct.txdelay` | `<float>` | Direct TX delay factor (>=0) |
| `flood.max` | `<int>` | Max flood hops (0-64) |
| `advert.interval` | `<int>` | Minutes (60-240, or 0 to disable) |
| `flood.advert.interval` | `<int>` | Hours (3-168, or 0 to disable) |
| `allow.read.only` | `on\|off` | Guest read-only access |
| `multi.acks` | `0\|1` | Extra ACK transmissions |
| `int.thresh` | `<int>` | Interference threshold |
| `agc.reset.interval` | `<int>` | Seconds (rounded to multiple of 4) |
| `owner.info` | `<string>` | `\|` translated to newlines, max 119 chars |
| `prv.key` | `<hex>` | Set private key (reboot to apply) |
| `adc.multiplier` | `<float>` | ADC calibration (0 = board default) |
| `bridge.enabled` | `on\|off` | Requires bridge support |
| `bridge.delay` | `<int>` | 0-10000 ms |
| `bridge.source` | `tx\|rx` | Packet source for bridge |
| `bridge.baud` | `<int>` | 9600-115200 (RS232 only) |
| `bridge.channel` | `<int>` | 1-14 (ESP-NOW only) |
| `bridge.secret` | `<string>` | Max 15 chars (ESP-NOW only) |

#### Temporary Radio

| Command | Args | Description |
|---------|------|-------------|
| `tempradio` | `<freq> <bw> <sf> <cr> <timeout-mins>` | Apply temporary radio params, auto-reverts after timeout |

#### Neighbors

| Command | Args | Description |
|---------|------|-------------|
| `neighbors` | — | List known neighbors |
| `neighbor.remove` | `<pubkey-hex>` | Remove a neighbor by pubkey |

#### Sensors

| Command | Args | Description |
|---------|------|-------------|
| `sensor list` | `[start-idx]` | List custom sensor variables (paginated) |
| `sensor get` | `<key>` | Get a sensor setting value |
| `sensor set` | `<key> <value>` | Set a sensor setting value |

#### GPS (if compiled with `ENV_INCLUDE_GPS`)

| Command | Args | Description |
|---------|------|-------------|
| `gps` | — | GPS status (on/off, fix, satellites) |
| `gps on` | — | Enable GPS |
| `gps off` | — | Disable GPS |
| `gps sync` | — | Sync time from GPS |
| `gps setloc` | — | Save current GPS coords to prefs |
| `gps advert` | `[none\|share\|prefs]` | Get/set advert location policy |

#### Power Saving

| Command | Args | Description |
|---------|------|-------------|
| `powersaving` | — | Show current power saving state |
| `powersaving on` | — | Enable power saving |
| `powersaving off` | — | Disable power saving |

#### Logging

| Command | Args | Description |
|---------|------|-------------|
| `log start` | — | Enable packet logging |
| `log stop` | — | Disable packet logging |
| `log erase` | — | Delete the log file |
| `log` | — | Dump log file to serial | Serial only |

### CLI Reply Size Limit

CLI replies are written into a 166-byte `temp[]` buffer starting at offset 5 (leaving room for the TXT_MSG header). The reply text is then sent back as a TXT_MSG with `TXT_TYPE_CLI_DATA`, subject to the same 160-byte content limit. In practice, replies are null-terminated C strings, so the effective max reply length is **~155 bytes** (160 - 5 header bytes, with the content starting at `temp[5]`).

### Important: Null Byte Limitation

Both CLI command content and replies are treated as **null-terminated C strings** throughout the firmware. The ACK hash calculation uses `strlen()` to determine message length, and `strncpy`/`strcpy` are used for storage. Any payload containing `0x00` bytes will be truncated at the first null. This is the primary constraint for binary data payloads like profile pictures — they must either avoid null bytes entirely or the firmware must be modified to use explicit length fields.

---

## Quick Reference

| What                    | Max Size  |
|-------------------------|-----------|
| LoRa packet payload     | 184 bytes |
| Hop path                | 64 bytes  |
| Text message content    | 160 bytes |
| ADVERT (min)            | 100 bytes |
| ACK                     | 4 bytes   |
| Addressed header        | 4 bytes   |
| Group header            | 3 bytes   |
| Anonymous request header| 35 bytes  |
