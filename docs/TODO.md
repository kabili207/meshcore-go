# Remaining work

The one list of what meshcore-go still lacks compared to MeshCore firmware v1.18.0,
plus a few things to verify. Every item was checked against the code on 2026-10-22.
When you finish one, delete it here. When you find a new gap, add it here, not in
the other docs.

For what already works, see [FEATURE_PARITY.md](FEATURE_PARITY.md). For how each
firmware release was analyzed, see [UPGRADE_1.17.md](UPGRADE_1.17.md) and
[UPGRADE_1.18.md](UPGRADE_1.18.md).

## Companion frame protocol

Partly handled:

- **`CMD_SET_OTHER_PARAMS`** keeps only the advert location policy. Manual
  contact adds, telemetry modes and multi-acks are dropped, and `SELF_INFO`
  reports them as zero.

Not handled at all (`ERR_CODE_UNSUPPORTED_CMD`), roughly by priority:

- **`CMD_SEND_CHANNEL_DATA`, `CMD_SEND_CONTROL_DATA`, `CMD_SEND_PATH_DISCOVERY_REQ`.**
  `BaseNode` can already send all three. For channel data, use firmware v1.18's
  limit, `codec.MaxGroupDataLength` (165), and reply `ERR_CODE_ILLEGAL_ARG` past it.
- **`CMD_SET_PATH_HASH_MODE`.** The router supports it.
- **`CMD_LOGOUT`, `CMD_HAS_CONNECTION`.**
- **`CMD_SIGN_START` / `CMD_SIGN_DATA` / `CMD_SIGN_FINISH`.**
- **`CMD_SEND_RAW_DATA`, `CMD_SEND_RAW_PACKET`.** Since v1.18, raw data's byte 1 is
  an encoded path length (hash size in the top 2 bits, hop count in the low 6),
  validated like any path.
- **`CMD_SET_CUSTOM_VAR`.** The getter exists.
- **`CMD_EXPORT_PRIVATE_KEY` / `CMD_IMPORT_PRIVATE_KEY`.** Needs a deliberate
  decision first, since it moves private keys over the wire.

Hardware commands (`CMD_REBOOT`, `CMD_FACTORY_RESET`, `CMD_SET_DEVICE_PIN`,
`CMD_GET_ALLOWED_REPEAT_FREQ`) stay unsupported on purpose.

Other:

- **The offline message queue is unbounded.** Firmware keeps 16. A companion that
  no app ever connects to stores every DM and channel message it hears.

## Repeater and room server

- **The room server has no on-demand `advert` CLI command.** The repeater has one,
  and the room already has an advert scheduler.
- **`setperm` can't add a new client by public key** in either role. It only
  changes existing clients and otherwise answers `ERR: client not found`.
- **The room server's `get radio` returns the radio model.** Firmware returns
  `freq,bw,sf,cr`.
- **Both send a flood advert on boot.** Firmware sends a zero-hop one
  (`advertSched.SendNow(true)` in `device/node/repeater.go` and `room.go`).

## Timing

Relay and reply delays match firmware. Still missing:

- **Airtime budget.** Firmware defers transmits to stay near a 50% duty cycle over a
  1-hour window.
- **Channel sensing (CAD)** before transmitting.
- **SNR-weighted receive delay.** Firmware ships it turned off, and our transports
  carry no SNR, so this is the lowest priority.

These only matter once a Go node fronts real RF, directly or through a bridge.

## Roles not started

- **Sensor.** Telemetry, GPS, min/max/avg history, alerts, and v1.18's subscribe and
  push telemetry. The wire format for subscribe and push is in
  [UPGRADE_1.18.md](UPGRADE_1.18.md), item 9. Companions already forward pushed
  telemetry to the app.
- **KISS modem** (firmware's `kiss_modem`, a radio pipe with a KISS TNC interface).
  The `feat/kiss-modem` branch is the other side of that link: a KISS *transport*
  so a Go node can drive such a modem.

## Observer

- **Move the observer publisher into meshcore-go.** It lives in
  meshcore-room-server, which already sends the format in
  [OBSERVER_MQTT.md](OBSERVER_MQTT.md). Moving it lets mesh-bridge and other apps
  share it.

## To verify

- **Direct routing over RF bridges.** An old report found direct sends failing
  where floods worked, including on 1-hop paths
  ([archive/COMPANION_NODE_GAPS.md](archive/COMPANION_NODE_GAPS.md), item 6).
  Path returns were sent reversed (`390b121`) and stored paths could carry the
  wrong hash size (`4857934`), but neither explains the 1-hop case. Retest on a
  real bridged mesh.

## Elsewhere

Found while working here, but the fixes belong to other projects:

- **mesh-mqtt-server** only lets non-observer clients read `packets` and `status`
  (`pkg/hooks/meshcore_observer.go`), so tools can't subscribe to `raw` or
  `neighbors`.
- **CoreScope** reads a `packets_recv` status stat that no uploader sends. The
  observer firmware sends `packets_received`.
