# Observer MQTT format

meshcore-go has no observer publishing of its own yet. An observer reports every packet it
hears, plus a periodic status message, to an MQTT broker as JSON, for dashboards
and analyzers. (`transport/mqtt` is something else: a packet bridge that carries
mesh traffic between nodes.)

This file compares the format as two uploaders produce it and two consumers read
it, then picks the format a Go publisher should emit. It also covers the
existing Go observer code in `meshcore-room-server` and `mesh-mqtt-server`.

| Project | Role | Version read |
|---|---|---|
| [Cisien/meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) | Uploader. A Python script that parses a repeater's serial packet log. What our users run. | `9b4e022` (2026-10-13) |
| [agessaman/MeshCore](https://github.com/agessaman/MeshCore) `observer-firmware` | Uploader. Repeater firmware that publishes directly. | `eaf455a6` (2026-10-20), based on upstream 1.18.0 |
| [Kpa-clawbot/CoreScope](https://github.com/Kpa-clawbot/CoreScope) | Consumer. Our main one. Go ingestor in `cmd/ingestor/`. | `0e3ce48` (2026-10-21) |
| [ipnet-mesh/meshcore-hub](https://github.com/ipnet-mesh/meshcore-hub) | Consumer. Python collector. | `9724e24` (2026-10-12) |

[ipnet-mesh/meshcore-mqtt](https://github.com/ipnet-mesh/meshcore-mqtt) is not an
observer. It bridges a companion radio's decoded app events (messages, contacts)
to topics like `meshcore/message/channel/0`, and hasn't been updated since
November 2025.

## The short version

Both consumers decode `raw` themselves and take almost everything from it.
Most of the envelope is decoration that nobody reads. The fields that do matter:

- **`raw`**: must be the complete, decodable frame. Hex, any case.
- **`hash`**: meshcore-hub groups receptions from different observers by exact
  string match, so it must be the firmware's 8-byte packet hash in uppercase hex.
  `dedupe.CalculatePacketHash` matches it, including the TRACE case. CoreScope
  recomputes the hash and ignores ours.
- **`SNR`, `RSSI`, `score`**: both consumers store these as real measurements in dB.
  Send real values or leave the key out. Never send `"0"` as a placeholder.
- **`timestamp`**: CoreScope flags the observer for clock skew when a timestamp
  without an offset is more than 15 minutes from its own clock. Send UTC with an
  offset.
- **`path`**: meshcore-hub uses its length as the hop count. A JSON array gives the
  right answer, and anything else is miscounted.
- **`origin`**: meshcore-hub sometimes reuses it as another node's display name, so
  make it a sensible name.
- **Topic**: `meshcore/{IATA}/{PUBKEY}/packets` and `/status`. Neither consumer
  ingests `/raw` or `/neighbors`.

## Uploader formats side by side

### Topics, QoS, will

| | meshcoretomqtt | agessaman firmware |
|---|---|---|
| Topics | `meshcore/{IATA}/{PUBLIC_KEY}/{status,packets,raw}`, templated per broker | `meshcore/{IATA}/{PUBKEY}/{status,packets,raw,neighbors}`; meshrank and custom templates |
| QoS | always 0 (1 is forced down to avoid retry storms) | status 1, others 0 |
| Status retained | no | yes, for most presets |
| Will | `offline` status, retained by default | none, and `offline` is never sent |
| IATA `XXX` | published as is | treated as unset; nothing is published |

### Packet message

| Field | meshcoretomqtt | agessaman firmware |
|---|---|---|
| `timestamp` | `datetime.now(utc).isoformat()`: `2026-10-21T14:03:07.123456+00:00` | same format |
| `time` | from the node's log line, node RTC | UTC |
| `date` | `D/M/YYYY`, day first, unpadded | `DD/MM/YYYY`, day first, padded |
| `len`, `packet_type`, `payload_len` | strings | strings |
| `route` | `F`/`D` | `F`/`D` |
| `raw` | uppercase hex | uppercase hex |
| `SNR`, `RSSI`, `score` | rx only, integer strings (`(int)` of dB, dBm, score x1000) | rx only; SNR `%.1f`; each omitted when unknown |
| `duration` | rx only, airtime in ms | not sent |
| `hash` | rx only, 16 uppercase hex | rx and tx, same |
| `path` | direct rx of PATH/REQ/RESPONSE/TXT_MSG only: `"A1 -> B2"`, the payload's source and destination hashes, not a route | direct packets with hops: array of lowercase hex hop hashes |
| tx | all transmissions (and `raw` holds the *last received* frame, a bug) | own adverts only, by default |

### Status message

| Field | meshcoretomqtt | agessaman firmware |
|---|---|---|
| `radio` | output of `get radio`: `freq,bw,sf,cr` | `"%.6f,%.1f,%d,%d"`, so `"910.525024,62.5,7,5"` |
| `model` | output of `board` | board name |
| `firmware_version` | output of `ver` | `v1.18.0` |
| `client_version` | `meshcoretomqtt/<ver>` | `meshcore/<fw ver>` |
| `repeat` | not sent | `on`/`off` |
| `stats` | `battery_mv`, `uptime_secs`, `debug_flags`, `queue_len`, `noise_floor`, `tx_air_secs`, `rx_air_secs`, `recv_errors` | same, but `errors` instead of `debug_flags`, plus `packets_sent`, `packets_received`, `internal_heap` and connection health |

### Auth

Both use the same JWT:

- Username is `v1_{PUBKEY}`, and the password is the token.
- Header: `{"alg":"Ed25519","typ":"JWT"}`, compact, base64url without padding.
- Claims: `publicKey` (uppercase), `iat`, `exp`, `aud`, `client`, and optional
  `owner` / `email`. meshcoretomqtt only sends `owner` and `email` over verified TLS.
- Signature: Ed25519 over `header.payload`, uppercase hex.
- Lifetime: 1 hour for meshcoretomqtt, 24 hours for the firmware.

The firmware also has fixed username/password presets. Neither uploader uses
MeshOMatic nonce auth any more; the firmware's `meshomatic` preset uses JWT.

## What the consumers read

| Field | CoreScope | meshcore-hub |
|---|---|---|
| Topic | `meshcore/#`; `parts[1]` IATA, `parts[2]` observer, routes on `parts[3]` | `{prefix}/+/+/{packets,status,internal}`; IATA ignored |
| `/raw`, `/neighbors` | raw dropped (it looks for `raw`, the payload has `data`); neighbors used | both dropped with a warning |
| `raw` | required string | required for decoding |
| `hash` | ignored, recomputed (lowercase) | **trusted**, used for cross-observer grouping |
| `SNR` | number or string, dB, optional | number or string, dB, optional |
| `RSSI`, `score` | number or string, optional | ignored |
| `path` | ignored | length used as hop count |
| `timestamp` | only for the clock-skew flag; packet time is ingest time | ignored |
| `date`, `time`, `route`, `len`, `duration` | ignored | ignored |
| `direction` | stored; tx excluded from who-heard-whom | ignored; tx stored as a reception |
| `origin` | observer name | observer name, sometimes reused for other nodes |
| `origin_id` | neighbors only | fallback key when decoding finds none |
| Status | `origin`, `model`, `firmware_version`, `client_version`, `radio`, `repeat`, and stats `battery_mv`, `uptime_secs`, `noise_floor`, `tx_air_secs`, `rx_air_secs`, `recv_errors`, `packets_sent`, `packets_recv` | stored whole, nothing parsed; bumps last-seen |
| `offline` will | refreshes metadata only; liveness ages out | **bumps last-seen**, so a dead observer looks alive |
| Retained status | metadata only, not liveness | stored like any other |

CoreScope reads `packets_recv`, which no uploader sends. The firmware's
`packets_received` is ignored.

## Recommended format for meshcore-go

The target is what both consumers handle correctly. Where the uploaders disagree
and no consumer cares, follow the firmware, since it's the actively maintained
format.

**Topics:** `meshcore/{IATA}/{PUBKEY}/packets` and `/status`, with the prefix
configurable. Don't publish `/raw` or `/neighbors` for now. Refuse to start
without a real IATA, rather than publishing `XXX`.

**Packet**, in this key order:

| Key | Value |
|---|---|
| `timestamp` | UTC, `2006-01-02T15:04:05.000000+00:00` |
| `hash` | `dedupe.CalculatePacketHash`, uppercase hex |
| `origin` | node name |
| `type` | `PACKET` |
| `direction` | `rx` / `tx` |
| `time` | UTC `15:04:05` |
| `date` | UTC `02/01/2006` (day first, padded) |
| `len` | `GetRawLength()`, string |
| `packet_type` | string |
| `route` | `D` for direct and transport-direct, else `F` |
| `payload_len` | string |
| `raw` | uppercase hex of `WriteTo()` |
| `origin_id` | uppercase pubkey |
| `SNR` / `RSSI` / `score` | only when a transport supplies them; otherwise omitted |
| `path` | direct packets with hops only: array of lowercase hex, `PathHashSize` bytes per hop |

Publish rx for everything heard, and tx only for our own adverts (the firmware
default).

**Status:** QoS 0, not retained, no will.

- Fields: `status: "online"`, `timestamp`, `origin`, `origin_id`, `model`,
  `firmware_version`, `client_version: "meshcore-go/<ver>"`, `repeat`.
- Add `radio` only when the host app configures nominal radio parameters. Leave it
  out otherwise, since a radio-less node has none.
- `stats` holds only values we actually have: `uptime_secs`, plus `packets_sent`
  and `packets_received` from `Router.Counters()`. Leave out battery, airtime,
  noise floor and error counts. Sending `packets_recv` as well would get the count
  into CoreScope, but that's a key no uploader uses. Better to fix it in CoreScope.

Dropping the will avoids meshcore-hub's dead-observer-looks-alive problem, and
CoreScope gets nothing from it. The firmware doesn't send one either.

**Auth:** the JWT above, uppercase hex signature, with `owner` / `email` optional.
Use a 1-hour lifetime renewed through the paho credentials provider on each
reconnect (as the room server does now). Plain username/password stays as the
alternative.

## Existing Go code

### meshcore-room-server `observer/`

Sends the recommended format above, on the `chore/meshcore-go-1.18` branch
(`9aba263`, `e8f44c6`, `e673411`). The fixes there:

- SNR (sent at 4× scale), RSSI and score (always `"0"`) are now omitted.
- Times are UTC with an offset, so CoreScope no longer flags clock skew, and the
  date is day first.
- `path` is a hex array, so meshcore-hub counts hops correctly.
- Status drops `radio: "MQTT"` and the always-zero stats, and sends
  `repeat: "off"`.
- The `offline` will is gone, because meshcore-hub read it as a sign of life.
- An enabled observer needs a real IATA code, not `XXX`.

Version strings follow the other uploaders: `firmware_version` is
`v1.18.0-meshcore-go-<commit>`, and `client_version` is
`meshcore-room-server/<version>`, where the version comes from a build flag or
the stamped commit.

### mesh-mqtt-server

Firmware and meshcoretomqtt observers are both accepted:

- The JWT header matches.
- The hex signature decodes in either case.
- Unknown claims are ignored.
- Only `raw` is read from packet messages.

Two gaps:

- Non-observer clients can only read `packets` and `status`
  (`pkg/hooks/meshcore_observer.go:177`). That's fine for CoreScope and
  meshcore-hub, which only use those.
- `RequireAudience` must match the audience the uploader is configured with. No
  firmware preset points at this broker, so firmware nodes need a custom slot
  with `mqttN.audience` set.

### mesh-bridge

No observer code. It would get observer support from the meshcore-go package.

## Porting to meshcore-go

Tracked in [TODO.md](TODO.md). The corrected room-server publisher is the
starting point.

Move the publisher into meshcore-go (for example `observer/`) using the format
above, so the room server, mesh-bridge and the examples share one
implementation. It isn't a `Transport`. It subscribes with
`Router.SetPacketMonitor`. Pieces:

- Ordered structs for the packet and status messages.
- The JWT, from `meshcore-room-server/observer/token.go`.
- Multiple brokers, each with its own topic prefix, IATA and auth.
- Optionally, an advert signature check before publishing
  (`crypto.VerifyAdvert`), like the firmware's `mqtt.advert.verify`.

About 500 to 700 lines plus tests.

Two router details:

- The monitor runs after the multipart gate (`device/router/router.go:447` vs
  `:459`), so MULTIPART receptions are never reported. The firmware reports them.
  Move the call above the gate.
- `Packet.SNR` exists, but none of our transports carry RF data, so the
  SNR/RSSI/score fields stay omitted unless a future transport supplies them.

## Agessaman firmware extras

Things the consumers don't use today, kept here for reference.

- **Neighbors** (`/neighbors`): `timestamp`, `origin`, `origin_id`,
  `total_neighbors`, `queried_neighbors`, `truncated`,
  `self{scopes, default_scope}`, and `neighbors[]` entries of
  `{pubkey, snr, heard_secs_ago, scopes, status}`. CoreScope uses entries with
  `status == "responded"`. Discovery reuses upstream's `ANON_REQ` regions request,
  sent direct and zero-hop.
- **Raw** (`/raw`): `origin`, `origin_id`, `timestamp`, `type: "RAW"`, `data`.
- **Recent additions** (Aug to Oct 2026):
  - Connection-health stats.
  - SNR/RSSI/score omitted rather than faked (`a91009e3`).
  - Optional advert signature check (`e53755a5`).
  - More presets.
  - Per-slot IATA, on the dev branch only.
- **Unmerged branches:** a map.meshcore.io uploader (`feat/meshcore-io-map-uploader`)
  and `feat/neighbors-rssi`.
- **Fault alerts** go out on the mesh as flood `GRP_TXT` on a configured channel.
- **Admin CLI over the mesh:**
  - Per slot: `mqttN.{preset, server, port, username, password, token, topic, audience, filter}`.
  - Shared: `mqtt.{origin, iata, status, packets, raw, rx, tx, advert.verify, interval, neighbors, neighbors.interval, owner, email}`.
  - Alerts: `alert.*`.
  - Secrets can be read back only over serial.
- **Out of scope for Go:** web config, WiFi, NTP, OTA, display, SNMP.
