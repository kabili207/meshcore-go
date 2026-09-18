# meshcore-go Feature Parity vs Official Firmware

Compares meshcore-go against the official MeshCore C++ firmware, role by role, plus
the shared base layer.

## Version baseline

- **Go (this repo):** wire-compatible with `FIRMWARE_VER_CODE 13`.
- **Firmware compared:** `~/Projects/PlatformIO/MeshCore` at `d9296435`
  (`companion-v1.17.1`). `FIRMWARE_VER_CODE` is still 13, unchanged since v1.16.0, so
  the wire baseline did not move. See `UPGRADE_1.17.md` for the v1.16.0 to v1.17.1
  delta and what it required.

Everything below was re-verified against the code on 2026-08-16. Claims here have a
history of drifting behind the implementation; when in doubt, trust the code and fix
this file.

Two structural facts shape everything:

1. The Go node is **transport-attached** (MQTT / serial / UDP / KISS), not a LoRa
   radio driver. GPS, display/UI, and sleep have no target in Go and are **N/A by
   design**, not gaps. Radio tuning and TX power are no longer in that bucket:
   `transport/kiss` sets them on the modem it drives, and `device/kiss` accepts them
   from a host. CAD is still out of reach, since the modem does its own sensing.
2. The firmware companion is a **phone bridge**: it exposes a serial/BLE frame
   protocol, and the real chat client is a phone app. Go implements **both** sides —
   `device/node` is the mesh/chat engine, and `device/companion` is a frame-protocol
   server a phone app can connect to over TCP or any stream.

## Roles at a glance

| Role | Firmware | Go | Overall parity |
|---|---|---|---|
| Companion / chat | `companion_radio` | `device/node/companion.go` + `device/companion` | Strong, both mesh and frame protocol |
| Repeater | `simple_repeater` | `device/node/repeater.go` | Strong; no airtime/CSMA |
| Room server | `simple_room_server` | `device/room/*` | Strong |
| Sensor | `simple_sensor` | none | Wire format + telemetry only |
| KISS modem | `kiss_modem` | `transport/kiss` + `device/kiss` | Full, both halves |
| Secure chat demo | `simple_secure_chat` | (companion covers it) | Reference app, not a gap |

---

## Shared / base layer

**Full parity:** packet codec (header bits, payload types, variable-width path hashes,
transport-code ordering), crypto (Ed25519 identity, Curve25519 ECDH, AES-128-ECB,
2-byte truncated HMAC MAC), flood routing gate + self-hash append + hop-priority, path
append/remove/reverse, region map including the exact `/regions2` binary format,
transport keys (Go implements the private-region keystore that firmware stubs as a
hardware TODO), trace forwarding, multipart ACK handling, packet dedup.

**Biggest gap: airtime and duty-cycle budgeting is still missing from the router.**
Firmware's `Dispatcher` runs a token-bucket airtime budget (~50% duty cycle, 1-hour
window), defers TX when budget is low, does CAD/channel sensing, applies SNR-weighted
RX flood delay (better-SNR nodes rebroadcast first), and randomizes flood rebroadcast
jitter. Go has p-persistent CSMA in `device/kiss` (carrier sense, persistence draw,
slot backoff, stuck-channel timeout) and `transport/kiss` blocks a send until the
modem reports it finished, so a node fronting a KISS radio does get channel access
control and TX backpressure. None of the rest exists: the router drains its queue
every 10ms
(`DefaultDrainInterval`) and almost always sends with `delay=0`. The queue does
support per-packet delay (`device/router/queue.go`) and uses it for
`PathSendDelay` (300ms on PATH packets), so the mechanism exists and is simply never
applied to airtime. Excusable for a transport-attached node, but any Go node fronting
real RF would misbehave (collisions, storms, duty-cycle non-compliance).

**Reply scoping** now matches firmware v1.17: a flooded reply mirrors the request's
transport scope, falls back to `Config.DefaultReplyScope`, and only goes un-scoped
when the requester did (`device/router/replypolicy.go`).

**Tiered flood caps** (`MaxFloodHops` / `MaxUnscopedFloodHops` / `MaxAdvertFloodHops`,
defaults 64/64/8) are a parity match as of v1.17, which added the same three tiers in
`RoutingPolicy.h`. Go had them first; this is no longer a Go-only extra.

**Shared CLI:** firmware's `CommonCLI` (~25 commands, ~40 config keys, used by all
roles) maps to a shared `device/cli` dispatcher that the room and repeater both mount.
The config/admin subset is implemented on both (get/set keys, `get acl`, `setperm`,
`clock`, `time`/`reboot` via opt-in callbacks, `region`, `stats-*`, flood caps,
`owner.info`, `advert.interval`, `multi.acks`); the repeater adds `advert`,
`advert.zerohop`, `neighbors`, `neighbor.remove`, and `discover.neighbors`. The
remaining firmware commands are hardware/radio (gps, sensor, log, ota, tempradio,
bridge.*, pwrmgt.*, radio tuning) and stay N/A. `stats-radio` returns `unsupported` in
both roles.

---

## Companion / chat node

Two layers, both implemented.

### Mesh / chat engine (`device/node`)

**Full:** contact management (add/update/remove/search/favorites/eviction, plus a
transient anon pool), DM send (plain/CLI/signed, chunking, direct-vs-flood, attempt
encoding), DM receive + decrypt, ACK matching via `ack.Tracker`, path learning (flood
to direct), advert processing, channel/group messages (GRP_TXT and GRP_DATA), client
login + keep-alive to repeaters and room servers, telemetry and status requests
(`SendTelemetryReq`, `SendStatusReq`), path reset / path discovery / trace initiation,
auto-ACK piggyback and multi-acks.

**Divergences:**
- Go defaults `MaxContacts` to 32 (firmware 100), plus 8 anon slots, so 40 total.
- `CMD_SEND_SELF_ADVERT` returns OK without actually sending an advert
  (`device/companion/companion.go`). Recurring adverts correctly default to disabled
  to match firmware, so a companion currently has no working way to advertise on
  demand through the frame protocol.

### Frame protocol server (`device/companion`)

A phone app can connect to a Go node today. `ListenAndServe` runs a TCP listener and
`Serve` works over any `io.ReadWriter` (a pty, for instance). The framing is the same
`'>'`/`'<'` + uint16-LE-length format the firmware uses on USB serial and, as of
v1.17, on Ethernet — so the same client code works against either.

**Implemented:** 35 dispatch arms covering 38 `CMD_*` codes, an offline message queue
drained by `CMD_SYNC_NEXT_MESSAGE`, and unsolicited pushes to connected sessions.
Unknown opcodes return `ERR_CODE_UNSUPPORTED_CMD`.

**Divergence worth fixing:** the offline queue is **unbounded**. Firmware uses a fixed
16-slot ring. A Go node that never has an app connect will grow the queue without
limit.

**Not dispatched** (23 constants defined, no handler). Hardware-bound and N/A:
`CmdReboot`, `CmdFactoryReset`, `CmdSetDevicePin`, `CmdGetAllowedRepeatFreq`,
`CmdSetOtherParams`. Real gaps, roughly in priority order:

- `CmdSendChannelData`, `CmdSendControlData`, `CmdSendBinaryReq`, `CmdSendAnonReq`,
  `CmdSendPathDiscoveryReq` — send paths `BaseNode` already implements internally, just
  not reachable from a connected app
- `CmdSetPathHashMode`, `CmdSetDefaultFloodScope`, `CmdSetFloodScopeKey` — config the
  router supports but an app cannot set
- `CmdLogout`, `CmdHasConnection` — session lifecycle
- `CmdSignStart` / `CmdSignData` / `CmdSignFinish` — message-signing sessions
- `CmdSendRawData`, `CmdSendRawPacket` — raw packet injection
- `CmdSetCustomVar` — the getter is implemented, the setter is not
- `CmdExportPrivateKey` / `CmdImportPrivateKey` — key portability; worth a deliberate
  decision rather than a default, since it moves private keys over the wire

**N/A by design:** BLE transport itself (Go speaks the framing, not GATT), radio/tx/
tuning/BLE-pin/GPS/buzzer prefs.

---

## Repeater

Data plane and control plane both in good shape.

**Full:** flood forwarding, direct forwarding (self-hash match, path pop, ACK
re-creation), loop detection (thresholds `{4,2,1}/{2,1,1}/{1,1,1}` match), region map +
region CLI, transport keys / scoped flood, self-advert scheduling, packet counters,
dedup, TRACE forwarding, tiered flood caps.

**Control plane:** admin login + ACL, the shared `device/cli` surface (admin-gated
`TXT_TYPE_CLI`), `GET_STATUS` / `GET_ACCESS_LIST` / `GET_NEIGHBOURS` / `GET_TELEMETRY`
as REQ types, owner-info / regions / clock as direct-routed ANON_REQ types
(`repeater_anon.go`), a dedicated neighbor table with per-neighbor SNR and heard
timestamps, node discovery (`repeater_discover.go`), and rate limiting
(`ratelimit.go`, mirroring firmware's `RateLimiter`: 4-per-2min for discovery,
4-per-3min for anon requests).

**Persistence:** opt-in via hooks. `OnRegionsChanged` / `OnSettingChanged` plus
`SetConfig` / `LoadConfig` round-trip node settings, and `ACLPersistence` persists the
access list. Nothing is persisted unless the host app wires these up.

**Missing:** airtime budget and CSMA backoff (see the shared-layer note).

**Behavioral note:** the Go repeater sends a flood advert on boot
(`advertSched.SendNow(true)`); firmware sends zero-hop.

---

## Room server

**Full / close:** sync loop (round-robin, 6s post-sync delay, 3-failure cap),
GET_TELEMETRY (guest to base-only), GET_ACCESS_LIST (admin-only), push to logged-in
clients with correct authorship (`SIGNED_PLAIN` carrying the author's 4-byte pubkey
prefix and original timestamp), adverts, path management, ACK receive, active-path
replay protection, open-room posting rights, 52-byte `ServerStats`, and a keep-alive
that is direct-only, honors `forceSince`, and appends the unsynced-count byte.

**Single dispatch path.** The legacy `HandlePacket` switch was removed; the event path
(`device/room/handlers.go`, driven by `RoomNode.dispatchToServer`) is the only one. The
room tests now drive that path through a shim (`device/room/eventbridge_test.go`) that
reproduces `BaseNode`'s packet-to-event conversion, since `device/room` cannot import
`device/node`. If a room test passes while the real node misbehaves, suspect that shim
first.

**Still open:**
- On-demand `advert` CLI command. `RoomNode` does build an advert scheduler and wire
  interval hooks; only the CLI command binding is missing.
- `setperm` cannot add a brand-new admin by pubkey — it searches existing clients and
  returns `ERR: client not found`. The repeater has the same limitation.
- `MemoryClientStore` defaults to RAM-only; persistence is opt-in via
  `WithPersistence`.

---

## Sensor role (mostly missing)

Firmware `SensorMesh` is a full node: self-telemetry (battery, and as of v1.17 MCU
temperature), 14 environment sensor chip families, GPS/NMEA location, full Cayenne LPP
codec, a time-series ring buffer with min/max/avg, telemetry request/response with a
3-tier permission mask, and threshold alerts with ACK tracking.

Go has the wire format plus telemetry plumbing: `NodeTypeSensor = 0x04` so adverts
parse, and both the room server and repeater answer `GET_TELEMETRY` via the shared
`telemetry.Provider` (the host app populates a CayenneLPP encoder, gated by the
firmware permission mask), using go-cayenne-lib.

Still missing: the sensor node type itself, drivers, GPS, time-series storage
(`ReqTypeGetMinMaxAvg = 0x04` is defined but handled nowhere), and alerts.

---

## KISS modem (full parity, both halves)

Firmware `KissModem` is a raw radio pipe: KISS TNC serial framing (FEND/FESC), raw
packet in/out, a CSMA TX state machine, and a `SETHARDWARE` sub-protocol (26
crypto/radio/telemetry ops). Go implements the wire format in `core/codec/kiss` and
both sides on top of it.

`transport/kiss` is the **host** half, a `transport.Transport` that drives a modem
over a serial port or any stream. It is the first path by which a Go node reaches
real RF. All 26 SetHardware sub-commands are exposed as methods. Received packets are
held briefly so the `RxMeta` frame that follows can populate `Packet.SNR`, which no
other transport in this repo sets. `SendPacket` waits for the modem's `TxDone`, so
the caller gets genuine airtime backpressure from a radio that holds one pending
packet.

`device/kiss` is the **modem** half: a server that presents a `Radio` to KISS hosts
over a stream or TCP. Since Go has no LoRa driver, the caller supplies the physical
layer, which makes the same code usable as a bridge that exposes an existing mesh
transport to standard KISS clients. Optional hardware hooks mirror the firmware's
callbacks and answer `NoCallback` when absent. It implements the p-persistent CSMA
state machine (TXDELAY / persistence / slot time / TXtail, carrier sense, and the
stuck-channel timeout), which is the one place airtime discipline exists in this
repo.

The companion protocol's `CmdSendRawData` remains unrelated (app-frame packet
injection, not a KISS TNC).

---

## Bottom line

- Wire protocol / crypto / codec: near-complete parity.
- Companion: both halves are real. The mesh engine is a solid DM/channel client, and
  the frame-protocol server means a phone app can drive a Go node over TCP. Bound the
  offline queue and make `CMD_SEND_SELF_ADVERT` actually advertise.
- Repeater: good forwarder with a working admin/config/stats surface, rate limiting,
  discovery, and opt-in persistence.
- Room server: functionally close to firmware, on a single dispatch path.
- KISS modem: complete on both sides, and the only route by which a Go node touches
  real RF.
- Sensor: not started.
- Systemic: no airtime or duty-cycle budget in the router. CSMA now exists, but only
  inside `device/kiss`; a node whose radio hangs off `transport/kiss` gets channel
  access control from the modem it is talking to, and nothing else does.
