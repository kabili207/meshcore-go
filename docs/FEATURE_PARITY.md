# meshcore-go Feature Parity vs Official Firmware

This document compares meshcore-go against the official MeshCore C++ firmware,
role by role, plus the shared base layer.

## Version baseline

- **Go (this repo):** targets MeshCore **v1.16.0** (recent commits, 6-byte extended ACKs).
- **Firmware compared:** `~/Projects/PlatformIO/MeshCore`. Initial analysis was done
  against a **v1.14.1** checkout, then re-verified against **v1.16.0**
  (`companion/room-server/repeater-v1.16.0`, all the same commit `07a3ca9e`,
  `FIRMWARE_VER_CODE 13`). The re-check results are below.

## v1.16.0 re-check: what changed

Updating the firmware to v1.16.0 resolved every item that was flagged as "version
skew." Go was clearly written against v1.16, so most v1.14.1 discrepancies were just
the old checkout.

**Resolved (were version skew, now confirmed matching):**
- **ACK dedup scheme.** v1.16 `SimpleMeshTables` uses a single unified 160-entry
  (`128+32`) table and deduplicates ACKs via `calculatePacketHash` like every other
  packet. The old separate 4-byte-CRC ACK table is gone. This is exactly Go's
  `PacketDeduplicator` design.
- **ACK payload size.** v1.16 `createAck` takes a caller-supplied length and builds
  the 6-byte extended plain-text ACK (extended attempt byte + random 6th byte,
  `BaseChatMesh.cpp:232-234`). Matches Go's `BuildAckPayloadExt`.
- **Serial frame size.** `MAX_FRAME_SIZE` is 176 in v1.16, matching Go's `MaxFrameSize`.
- **Packet hash function.** `calculatePacketHash` = `SHA256(type + [path_len if TRACE]
  + payload)`, byte-for-byte what Go computes.
- **Room stats field layout.** The first 52 bytes of the v1.16 `ServerStats`
  (`err_events`, `n_posted`, `n_post_push`, etc.) match Go's struct exactly. These
  fields did not exist in v1.14.1.

**Persist (real gaps, not version skew, still present in v1.16):**
- **Room `ServerStats` size** was a 4-byte over-send (Go emitted 56, firmware expects
  52). **Fixed** on 2026-07-03; see the Fixed section below.
- **Open-room posting rights** diverged (Go granted `ReadOnly(1)` and let it post,
  firmware grants `GUEST` and blocks it). **Fixed** on 2026-07-03; see below.
- **Active-path replay protection, airtime/duty-cycle/CSMA, forged-advert
  forwarding, overheard direct-ACK, multipart reassembler.** All version-independent;
  unchanged in v1.16.
- **Shared `CommonCLI`.** v1.16 rewrote it heavily (~1100 lines changed) and grew the
  command surface. Go now has a shared `device/cli` dispatcher (mounted by both the
  room and repeater) covering the config/admin subset; the remaining gap is all
  hardware/radio commands (gps, sensor, log, ota, bridge, pwrmgt) that are N/A for a
  transport-attached node. See the "Fixed" notes below.
- **Sensor role.** v1.16 expanded sensors (RAK12035 soil moisture, a large
  `EnvironmentSensorManager` rewrite), widening the gap. Still absent in Go.

**New in v1.16 (watch these):**
- **`PAYLOAD_TYPE_GRP_DATA` (0x06) inner format changed** from `timestamp, blob` to
  `data_type(uint16), data_len, blob` (plus a new `MAX_GROUP_DATA_LENGTH`). Go does
  not decrypt group data yet (TODO), so it is unaffected now, but any future group-data
  support must use the new layout. `GRP_TXT` (0x05, text) is unchanged.
- **`CMD_SEND_RAW_PACKET = 65`** added to the companion serial protocol. Go's serial
  constants stop at `CmdGetDefaultFloodScope = 64`, so Go is one command behind (moot
  until Go implements the frame protocol).
- No new mesh payload types (still 0x00-0x0B + 0x0F); Go already has all of them.

## Fixed since analysis (2026-07-03)

Four correctness bugs found during this comparison are now fixed (see
`docs/PARITY_PLAN.md` for the remaining work):

1. **Room `ServerStats` size (56 → 52 bytes).** Dropped the erroneous `NRecvErrors`
   field (a `RepeaterStats` member) so the GET_STATUS response matches the v1.16
   room server layout. `device/room/stats.go`.
2. **Open-room posting rights.** `resolvePermissions` now grants `PermACLGuest` (not
   `PermACLReadOnly`) for `AllowReadOnly` logins, matching firmware. The existing
   posting gate already blocks guests, so open rooms are now correctly read-only.
   `device/room/login.go`.
3. **Room active-path replay protection.** `TextMessageReceived` now carries the
   sender `Timestamp`, and the event-based `HandleTextMessage` rejects any message
   whose timestamp is not newer than the client's last. Stops duplicate posts on
   retransmission and old-message replay. `device/event/message.go`,
   `device/node/dispatch.go`, `device/room/handlers.go`. Regression tests added.
4. **Companion nil-`Contacts` panic.** `NewCompanion` now creates the documented
   default `ContactManager` (MaxContacts=256, OverwriteWhenFull) when
   `Contacts` is nil, instead of passing nil through. `device/node/companion.go`.

Two structural facts shape everything below:

1. The Go node is **transport-attached** (MQTT / serial), not a LoRa radio driver.
   Radio tuning, TX power, CAD, GPS, display/UI, and sleep have no target in Go.
   These are marked **N/A by design**, not gaps.
2. The firmware companion is a **phone bridge** (it exposes a serial/BLE frame
   protocol and the real chat client is a phone app). The Go companion **is** the
   application. So companion parity splits into mesh/chat behavior (Go is strong)
   and the frame protocol (unimplemented in Go).

## Roles at a glance

| Role | Firmware | Go | Overall parity |
|---|---|---|---|
| Companion / chat | `companion_radio` | `device/node/companion.go` | Mesh/chat strong; serial/BLE frame protocol absent |
| Repeater | `simple_repeater` | `device/node/repeater.go` | Data plane strong; control plane (CLI/ACL/stats) absent |
| Room server | `simple_room_server` | `device/room/*` | Closest role; several behavioral divergences |
| Sensor | `simple_sensor` | none | Missing entirely |
| KISS modem | `kiss_modem` | none | Missing entirely |
| Secure chat demo | `simple_secure_chat` | (companion covers it) | Reference app, not a gap |

---

## Shared / base layer

Strong parity on the wire-facing pieces, one large systemic gap.

**Full parity:** packet codec (header bits, payload types, variable-width path
hashes, transport-code ordering), crypto (Ed25519 identity, Curve25519 ECDH,
AES-128-ECB, 2-byte truncated HMAC MAC), flood routing gate + self-hash append +
hop-priority, path append/remove/reverse, region map including the exact
`/regions2` binary format, transport keys (Go implements the private-region
keystore that firmware stubs as a hardware TODO), trace forwarding.

**Biggest gap: airtime / duty-cycle / CSMA is entirely missing.** Firmware's
`Dispatcher` runs a token-bucket airtime budget (~50% duty cycle, 1-hour window),
defers TX when budget is low, does CAD/channel sensing, applies SNR-weighted RX
flood delay (better-SNR nodes rebroadcast first), and randomizes flood rebroadcast
jitter. Go has none of it: the router drains its queue every 10ms and sends
immediately with `delay=0`. Partly excusable for a transport-attached node, but any
Go node fronting real RF would misbehave (collisions, storms, duty-cycle
non-compliance).

**Correctness items:**
- Forged adverts get re-flooded. Firmware verifies advert signatures before
  forwarding; Go verifies at the app layer (`contact.ProcessAdvert`) after the
  router already rebroadcast, and never marks invalid adverts do-not-retransmit.
- Overheard direct-ACK resolution missing. Firmware fires `onAckRecv` for an ACK
  transiting through it even when it is not the next hop; Go only resolves
  hash-matching ACKs locally.
- Multipart reassembler mismodels the protocol. Firmware's multipart is used only
  for ACKs, where each fragment is a complete inner ACK handled independently. Go's
  general `Reassembler` concatenates fragments; a bug if multipart ACKs route
  through it. Confirm which path the node uses.
- Reserved path-hash mode 3 not rejected (firmware drops it); 32-byte advert
  appdata cap not enforced before signing.

**Version-skew items (resolved at v1.16.0):** ACK dedup scheme and 4-vs-6-byte ACK
payload both matched v1.16. See the v1.16.0 re-check section above.

**Shared CLI:** firmware's `CommonCLI` (~25 commands, ~40 config keys, used by all
roles) now maps to a shared `device/cli` dispatcher that the room and repeater both
mount. The config/admin subset is implemented on both (get/set keys, `get acl`,
`setperm`, `clock`, `time`/`reboot` via opt-in callbacks, `region`, `stats-*`, flood
caps, `owner.info`); the repeater adds `advert`, `neighbors`, `neighbor.remove`,
`discover.neighbors`, `advert.interval`, and `multi.acks`. The remaining firmware
commands are hardware/radio (gps, sensor, log, ota, tempradio, bridge.*, pwrmgt.*,
radio tuning) and stay N/A for a transport-attached node.

---

## Companion / chat node

**Full:** contact management (add/update/remove/search/favorites/eviction), DM send
(plain/CLI/signed, chunking, direct-vs-flood, attempt encoding), DM receive +
decrypt, ACK matching via `ack.Tracker`, path learning (flood to direct), advert
processing. The prior `COMPANION_NODE_GAPS.md` items are mostly resolved
(`NewPacket`, `BuildPlainTextAck`, `ReverseFloodPath`, `updateContactPathFromFlood`,
the `TxtTypePlain` vs `TxtTypeCLI` subtlety).

**True mesh-level gaps:**
1. Channel/group messages. **Fixed** (2026-07-03): `BaseNode` has a channel-key
   store, decrypts GRP_TXT/GRP_DATA on receive, and sends via `SendChannelText`/
   `SendChannelData`; the companion registers the "Public" channel by default.
2. Client-side login to repeaters/room servers + keep-alive session. **Fixed**
   (2026-07-03): `CompanionNode.SendLogin`/`SendKeepAlive` with a `LoginResponse`
   event and `connection.Manager`-tracked sessions. (Original gap text below.)
   Codec has
   `ReqTypeLogin`/`ReqTypeKeepalive`; no client helper to initiate one.
3. Telemetry request send helper.
4. Path reset / path-discovery / trace initiation helpers. **Fixed** (2026-07-03):
   `ResetPath`, `SendPathDiscovery`, and `SendTrace`; completed traces surface as a
   `TraceReceived` event.
5. Auto-ACK piggyback + multi-acks. **Fixed** (2026-07-03): flood-received DMs
   piggyback the ACK into the path-return (one packet), and `ExtraAckTransmits`
   sends redundant multipart ACKs on direct paths.

**N/A by design:** the serial/BLE frame protocol (~55 `CMD_*` handlers; Go has the
constants in `core/codec/serial` but nothing dispatches them), the 16-slot offline
message queue (Go uses synchronous event callbacks), radio/tx/tuning/BLE-pin/GPS/
buzzer prefs, message-signing sessions, key import/export.

**Divergences:** Go auto-schedules adverts on a timer; the firmware companion
advertises only on demand. Go defaults `MaxContacts` to 32 (firmware 100).
The doc/code bug where `NewCompanion` passed a nil `Contacts` store through (panic
on first use) is **fixed** (2026-07-03): it now builds the documented default
256-contact manager.

---

## Repeater

Data plane at strong parity; control plane essentially absent (the node's own
comment: "No text message handling, ACK tracking, or keep-alive").

**Full:** flood forwarding, direct forwarding (self-hash match, path pop, ACK
re-creation), loop detection (thresholds `{4,2,1}/{2,1,1}/{1,1,1}` match), region
map + region CLI, transport keys / scoped flood, self-advert scheduling, packet
counters, dedup, TRACE forwarding. Go adds tiered flood caps (unscoped/advert)
firmware lacks.

**Missing (control plane):**
- Admin login + ACL. **Fixed** (Phase 3): repeater authenticates admin/guest via
  `acl` and gates its request/CLI surface.
- CLI command set. **Fixed** (2026-07-03): the repeater mounts a shared `device/cli`
  dispatcher (admin-gated `TXT_TYPE_CLI`) with get/set keys and commands. Keys:
  name/lat/lon, path.hash.mode, loop.detect, flood.max, flood.max.advert,
  flood.max.unscoped, repeat, advert.interval, flood.advert.interval, multi.acks,
  owner.info, plus read-only public.key/role/acl. Commands: ver, clock, time, reboot,
  advert(.zerohop), neighbors, neighbor.remove, discover.neighbors, password, setperm,
  region, stats-packets/core/radio. `time`/`reboot` are gated behind opt-in
  `OnSetClock`/`OnReboot` callbacks (a bridged node keeps its host clock). Not a full
  ~80-command hardware surface (radio/gps/log/ota are N/A), but the config/admin
  subset is there.
- Stats / telemetry / neighbor / owner-info request responses. **Fixed**
  (Phase 3 + 2026-07-03): `GET_STATUS`, `GET_ACCESS_LIST`, `GET_NEIGHBOURS`, and
  `GET_TELEMETRY` answered (REQ types); owner-info, regions, and clock answered as
  direct-routed ANON_REQ types (`repeater_anon.go`), rate-limited by an `anon_limiter`
  (4 per 3 min) and reusing the `owner.info` config value. Telemetry uses a pluggable
  `telemetry.Provider` (shared `device/telemetry`), encoding CayenneLPP via
  go-cayenne-lib; guests are limited to base telemetry.
- Neighbor table. **Fixed** (Phase 3 + 2026-07-03): the repeater has a dedicated
  `neighborTable` with per-neighbor SNR and heard-timestamp, sorted snapshots
  (`GET_NEIGHBOURS`), and a `neighbor.remove` CLI command. (Generic `ContactInfo`
  still stores no SNR, but the repeater no longer relies on it for neighbors.)
- Rate limiters, airtime budget, CSMA backoff, node discovery, pref persistence.
  All absent; nothing configured survives a restart.

**Behavioral note:** the Go repeater sends a flood advert on boot; firmware sends
zero-hop.

Much of the needed logic lives in `device/room` and just needs wiring onto
`BaseNode`'s event pipeline.

---

## Room server

The most complete Go role. Caveat: Go has two dispatch paths (legacy `HandlePacket`
and event-based); `RoomNode` wires only the event path, and some capabilities are
more complete in the unused legacy path.

**Full / close:** sync loop (round-robin, 6s post-sync delay, 3-failure cap),
GET_TELEMETRY (guest to base-only), GET_ACCESS_LIST (admin-only), push to logged-in
clients, adverts, path management, ACK receive.

**Highest-impact divergences:**
1. Replay protection in the active text path. **Fixed** (2026-07-03): the event now
   carries the sender timestamp and `HandleTextMessage` rejects non-newer messages.
2. Open rooms were writable in Go. **Fixed** (2026-07-03): open login now grants
   `Guest`, which the posting gate blocks.
3. Pushed posts lose authorship. **Fixed** (2026-07-03): the room pushes
   `SIGNED_PLAIN` with the author's 4-byte pubkey prefix and original timestamp, keys
   the push-ACK by the client pubkey, and the companion auto-ACKs signed messages.
4. Stats struct size mismatch. **Fixed** (2026-07-03): Go now emits 52 bytes.
5. Admin CLI surface. **Mostly fixed** (2026-07-03): the room now has `password`
   (change admin password), `get acl`, `time`/`reboot` via opt-in
   `OnSetClock`/`OnReboot` callbacks, flood caps, `owner.info`, and `stats-*`.
   `clock`/`clock sync` now only report (a bridged node keeps its host clock;
   client-driven clock override is intentionally opt-in). Still open: on-demand
   `advert` (the room has no advert scheduler; the app drives adverts), and `setperm`
   adding a brand-new admin by pubkey. `MemoryClientStore` now has opt-in persistence
   (`WithPersistence`, admins survive restart) but defaults to RAM-only.

**Keep-alive** is thinner: Go sends a bare ACK, missing the unsynced-count byte,
`forceSince` handling, and the direct-only restriction.

---

## Sensor role (missing entirely)

Firmware `SensorMesh` is a full node: self-telemetry (battery), 14 environment
sensor chip families, GPS/NMEA location, full Cayenne LPP codec, time-series ring
buffer with min/max/avg, telemetry request/response with a 3-tier permission mask,
and threshold alerts with ACK tracking.

Go has the wire format plus the telemetry plumbing: `NodeTypeSensor = 0x04` so adverts
parse, and both the room server and repeater answer `GET_TELEMETRY` via the shared
`telemetry.Provider` (host app populates a CayenneLPP encoder, gated by the firmware
permission mask). CayenneLPP encoding uses go-cayenne-lib. Still missing for a full
sensor node: the sensor node type itself, drivers, GPS, and time-series storage
(`ReqTypeGetMinMaxAvg = 0x04` defined but never handled), plus alerts.

---

## KISS modem (missing entirely)

Firmware `KissModem` is a raw radio pipe: KISS TNC serial framing (FEND/FESC), raw
packet in/out, a CSMA TX state machine, and a `SETHARDWARE` sub-protocol (~26
crypto/radio ops). `grep` for kiss/tnc across the Go tree returns zero hits. The
companion serial protocol's `CmdSendRawData = 25` is unrelated (app-frame packet
injection, not a KISS TNC).

---

## Bottom line

- Wire protocol / crypto / codec: near-complete parity.
- Room server: functionally close, but fix the active-path replay gap, the open-room
  posting-rights inversion, and post authorship before treating it as
  firmware-compatible.
- Companion: solid DM client; needs channel messages, client login, and telemetry to
  be a full chat node. The phone-bridge frame protocol is a separate, unbuilt layer.
- Repeater: good forwarder, now with an admin/config/stats CLI surface (login + ACL,
  get/set keys, stats, neighbor management) via the shared `device/cli`.
- Sensor and KISS modem: not started.
- Systemic: no airtime/duty-cycle/CSMA anywhere. The shared `CommonCLI` gap is closed
  for the config/admin subset (`device/cli`); only hardware/radio commands remain N/A.
</content>
</invoke>
