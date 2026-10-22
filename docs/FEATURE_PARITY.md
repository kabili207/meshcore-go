# meshcore-go Feature Parity vs Official Firmware

Compares meshcore-go against the official MeshCore C++ firmware, role by role, plus
the shared base layer. This file describes what works and where Go differs on
purpose. Gaps are tracked in one place, [TODO.md](TODO.md).

## Version baseline

- **Go (this repo):** reports `FIRMWARE_VER_CODE 14` and `v1.18.0`.
- **Firmware compared:** `companion-v1.18.0` (`81dbae59`) in
  `~/Projects/PlatformIO/MeshCore`. See `UPGRADE_1.17.md` and `UPGRADE_1.18.md`
  for each release's delta and what it required.

Reviewed against the code on 2026-10-22. Claims here have a history of drifting
behind the implementation; when in doubt, trust the code and fix this file.

Two structural facts shape everything:

1. The Go node is **transport-attached** (MQTT / serial / UDP), not a LoRa radio
   driver. Radio tuning, TX power, CAD, GPS, display/UI, and sleep have no target in
   Go. These are **N/A by design**, not gaps.
2. The firmware companion is a **phone bridge**: it exposes a serial/BLE frame
   protocol, and the real chat client is a phone app. Go implements **both** sides —
   `device/node` is the mesh/chat engine, and `device/companion` is a frame-protocol
   server a phone app can connect to over TCP or any stream.

## Roles at a glance

| Role | Firmware | Go | Overall parity |
|---|---|---|---|
| Companion / chat | `companion_radio` | `device/node/companion.go` + `device/companion` | Strong, both mesh and frame protocol |
| Repeater | `simple_repeater` | `device/node/repeater.go` | Strong; relay delays, no airtime budget/CSMA |
| Room server | `simple_room_server` | `device/room/*` | Strong |
| Sensor | `simple_sensor` | none | Wire format + telemetry only |
| KISS modem | `kiss_modem` | none | Not started |
| Secure chat demo | `simple_secure_chat` | (companion covers it) | Reference app, not a gap |

---

## Shared / base layer

**Full parity:** packet codec (header bits, payload types, variable-width path hashes,
transport-code ordering), crypto (Ed25519 identity, Curve25519 ECDH, AES-128-ECB,
2-byte truncated HMAC MAC), flood routing gate + self-hash append + hop-priority, path
append/remove/reverse, region map including the exact `/regions2` binary format,
transport keys (Go implements the private-region keystore that firmware stubs as a
hardware TODO), trace forwarding, multipart ACK handling, packet dedup.

**Timing.** The send delays that keep neighbors from talking over each other match
firmware:

- **Relays:** a random wait of up to 5 × airtime × `txdelay` (0.5) for floods and
  `direct.txdelay` (0.3) for direct packets. Airtime is estimated by a port of
  RadioLib's time-on-air formula, from `RadioParams` (default 869.618,62.5,8,5).
- **Forwarded ACKs:** the multi-ack copies go first, 300ms apart, and relayed
  multi-acks wait for the copies still coming.
- **Replies:** responses wait 300ms, CLI replies 600ms (300ms on the room server),
  text ACKs 200ms.

The airtime budget, CAD and the SNR-weighted receive delay are not implemented
(see [TODO.md](TODO.md)), so a Go node fronting real RF has no duty-cycle limit.

**Reply scoping** matches firmware: a flooded reply mirrors the request's transport
scope, falls back to `Config.DefaultReplyScope`, and only goes un-scoped when the
requester did (`device/router/replypolicy.go`). Anonymous requests are scoped the
same way.

**Paths** keep their own hash size when sent direct, and path returns carry the
path as received, as firmware's do.

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

Also binary and anonymous requests (`SendBinaryReq`, `SendAnonReq`), unmatched
responses such as sensor pushes reported as `UnhandledResponse`, login failures,
and remote CLI from contacts with the remote-CLI flag (`SendCLIReply`).

### Frame protocol server (`device/companion`)

A phone app can connect to a Go node today. `ListenAndServe` runs a TCP listener and
`Serve` works over any `io.ReadWriter` (a pty, for instance). The framing is the same
`'>'`/`'<'` + uint16-LE-length format the firmware uses on USB serial and, as of
v1.17, on Ethernet — so the same client code works against either.

**Implemented:** 41 of the 59 `CMD_*` codes are dispatched, with an offline message
queue drained by `CMD_SYNC_NEXT_MESSAGE` and unsolicited pushes to connected
sessions. Unknown opcodes return `ERR_CODE_UNSUPPORTED_CMD`. This includes the v1.18
companion CLI (`CMD_RUN_CLI_COMMAND`), `CMD_SEND_BINARY_REQ` and `CMD_SEND_ANON_REQ`,
with replies and unmatched responses forwarded as `PUSH_CODE_BINARY_RESPONSE`, and
login failures pushed as `PUSH_CODE_LOGIN_FAIL`.

Three of the dispatched codes are acknowledged without effect, and 14 of the
undispatched ones are real gaps. Both lists are in [TODO.md](TODO.md).

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

**Timing:** relays wait firmware's random delay, sized by `RepeaterConfig.Radio`
and the `txdelay` / `direct.txdelay` CLI keys (defaults 0.5 / 0.3), and forwarded
ACKs send their multi-ack copies first. Discovery responses wait four times the
flood delay.

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

**Forwarding:** off by default, as in firmware. `set repeat on` replies
`ERR - repeat now deprecated`, and `RoomConfig.ForwardPackets` is a deprecated
opt-in.

**Persistence:** `MemoryClientStore` is RAM-only unless built with
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

The sensor node itself is not started; see [TODO.md](TODO.md).

---

## KISS modem (missing entirely)

Firmware `KissModem` is a raw radio pipe: KISS TNC serial framing (FEND/FESC), raw
packet in/out, a CSMA TX state machine, and a `SETHARDWARE` sub-protocol (~26
crypto/radio ops). There's no Go equivalent. The `feat/kiss-modem` branch works on
the other end of that link, a KISS transport so a Go node can drive such a modem.

---

## Deliberate differences

Places where Go behaves differently from firmware on purpose. Each is recorded
where it was decided.

- **CLI reply style.** The repeater and room server CLI share Go's dispatcher, which
  answers `get` with the bare value, `set` with `OK`, and errors as `Error: ...`.
  Firmware answers `> value` and words errors per command. The companion CLI uses
  firmware's exact strings, since apps parse them.
- **Transport code 0** is treated as fully unscoped: the wildcard's deny flag and
  the unscoped hop cap apply. Firmware applies neither. See
  [UPGRADE_1.18.md](UPGRADE_1.18.md), item 4, and `isUnscoped` in
  `device/router/transport.go`.
- **Anonymous contacts** keep their learned path when a real advert replaces them,
  and are left alone when the advert isn't auto-added. Firmware drops both. Our
  repeaters and room servers route replies to logged-in clients through these
  entries (`device/contact/helpers.go`).
- **Region names** are copied byte-wise, not truncated on a UTF-8 boundary, matching
  firmware's `RegionMap` (only advert names get UTF-8 truncation). See
  [UPGRADE_1.17.md](UPGRADE_1.17.md), item 4.
- **`MaxContacts` defaults to 32** (firmware 100), plus 8 anonymous slots.
- **`CMD_SET_DEVICE_TIME` is ignored.** A transport-attached node keeps its host
  clock.
- **The room server forwards only on request.** `RoomConfig.ForwardPackets` still
  works, though firmware no longer allows it.

## Bottom line

- Wire protocol, crypto, codec, routing and timing of relays and replies: at
  parity with v1.18.0.
- Companion: both halves are real. The mesh engine is a solid DM/channel client, and
  the frame-protocol server lets a phone app drive a Go node over TCP. The remaining
  frame-protocol gaps are in [TODO.md](TODO.md).
- Repeater: a full forwarder with firmware's relay delays, admin/config/stats,
  rate limiting, discovery, and opt-in persistence.
- Room server: functionally close to firmware, on a single dispatch path.
- Sensor and KISS modem: not started.
- Systemic: no airtime budget, duty-cycle limit or CSMA, which would matter if a
  LoRa radio transport were ever added.
