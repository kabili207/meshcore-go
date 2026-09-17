# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions aim to
follow [Semantic Versioning](https://semver.org/). Pre-1.0, minor releases may
contain breaking changes; those are called out explicitly below.

## [Unreleased]

### Changed (breaking)

- **Group channels are identified by their key, not their 1-byte hash.**
  `BaseNode.SendChannelText`, `BaseNode.SendChannelData`, and the
  `CompanionNode.SendChannelText` wrapper now take the channel key (`[]byte`)
  instead of the channel hash (`uint8`). `RemoveChannel` now takes the key as
  well. `AddChannel(key []byte) uint8` is unchanged.

  *Why:* a channel hash is only the first byte of `SHA256(key)`, so two channels
  can collide on it. Identifying a channel by hash left sends ambiguous under a
  collision (no way to know which key to encrypt with).

  *Migration:* pass the channel key wherever you previously passed the hash. The
  hash is derived internally. Sends no longer require the channel to be
  registered first, so `SendChannelText`/`SendChannelData` no longer return an
  "unknown channel" error.

- **Room telemetry uses a shared, encoder-based provider.** The room's
  `room.TelemetryProvider` interface (`GetTelemetry(permMask uint8) []byte`) was
  removed in favor of `telemetry.Provider`
  (`QuerySensors(permissions uint8, enc cayennelpp.Encoder)`) from the new
  `device/telemetry` package. `ServerConfig.Telemetry` now takes a
  `telemetry.Provider`.

  *Migration:* implement `QuerySensors` and populate the passed CayenneLPP encoder
  instead of returning pre-encoded bytes. Encoding uses
  `github.com/TheThingsNetwork/go-cayenne-lib`. The permission mask semantics are
  unchanged (guests get base telemetry only).

- **The MQTT transport defaults to the EastMesh firmware's bridge format.**
  `mqtt.Config` gained `Framing` and `Secret`. The zero value, `FramingBridge`,
  wraps each packet in a magic + Fletcher-16 frame XORed with `Secret` and
  defaults the topic to `meshcore/bridge/packets`, matching the MQTT bridge in
  [xJARiD/MeshCore-EastMesh](https://github.com/xJARiD/MeshCore-EastMesh).

  *Why:* the [vrybdpkt/MeshCore](https://github.com/vrybdpkt/MeshCore) fork the
  transport was aligned with has had no commits since February 2026. EastMesh
  is actively maintained by the Eastern Australia mesh network.

  *Migration:* to keep talking to vrybdpkt repeaters, set
  `Framing: mqtt.FramingRaw`. That restores bare-packet payloads and the
  `meshcore/bridge` default topic. The two formats can't share a topic: each
  side drops the other's messages.

### Added

- Firmware-format `ver`/`version` CLI reply: `cli.FirmwareVersion` (the targeted
  firmware version, e.g. `v1.16.0`) plus `cli.FormatVersion` build the
  `"<version> (Build: <date>)"` string the phone apps parse to gate editing. Both
  the room and repeater now accept `version` as an alias for `ver` and expose a
  `FirmwareBuildDate` config field for the caller to supply the build date. Set
  `Version` to override the whole reply verbatim. Previously `ver` returned the
  bare string `meshcore-go`.
- Shared `device/telemetry` package: the `Provider` interface, `TELEM_PERM_*` mask
  bits, `ChannelSelf`, and `Mask`/`Encode` helpers. The repeater
  (`RepeaterConfig.Telemetry`) and room both answer `GET_TELEMETRY` through it.
- Repeater ANON_REQ handlers for regions, owner-info, and clock
  (direct-routed only, rate-limited to 4 per 3 minutes).
- Shared CLI dispatcher (`device/cli`) mounted by the room and repeater, covering
  the firmware `CommonCLI` config/admin subset: get/set keys, `get acl`, `setperm`,
  `clock`, `time`/`reboot` (via opt-in `OnSetClock`/`OnReboot` callbacks), `region`,
  `stats-*`, flood caps, and `owner.info`; plus repeater-only `advert`,
  `neighbors`, `neighbor.remove`, `discover.neighbors`, `advert.interval`,
  `flood.advert.interval`, `multi.acks`, and room-only `password`.
- Opt-in persistence: `RepeaterConfig.ACLPersistence` and the room's
  `MemoryClientStore.WithPersistence` (both reuse `acl.FileStore`; admins survive a
  restart, transient state does not), plus `contact.FileContactStore`.
- Repeater control plane: ACL-based admin/guest login, `GET_STATUS`,
  `GET_ACCESS_LIST`, `GET_NEIGHBOURS`, a directly-heard neighbor table, and node
  discovery.
- Companion client features: channel messaging, client login + keep-alive,
  telemetry requests, path reset/discovery, and TRACE.
- `event.GroupDataReceived` now carries a `DataType` field (the firmware GRP_DATA
  `data_type`), so consumers can dispatch on the payload format.
- Programmatic access to CLI config keys. `cli.Dispatcher` gained `Set`, `Load`
  (applies without firing the AfterSet/persist hook), and `Get`; `RepeaterNode`
  and the room `Server` expose `SetConfig`/`LoadConfig`/`GetConfig`. `LoadConfig`
  lets an app restore settings from its own store at startup without writing them
  straight back. Unknown or read-only keys return `cli.ErrUnknownKey`.
- `codec.EncodeBridgeFrame` / `codec.DecodeBridgeFrame`, the datagram framing the
  firmware's ESP-NOW bridge and the EastMesh MQTT bridge share.

### Fixed

- **Group channels that share a 1-byte hash now all decode.** `BaseNode` keeps
  every key registered under a hash and tries each on inbound `GRP_TXT`/`GRP_DATA`,
  letting MAC verification select the right one. This matches firmware's
  `searchChannelsByHash` behavior. Previously the last-registered key won and any
  colliding channel silently stopped decoding.
- **Non-plain group text is now dropped.** Inbound `GRP_TXT` with a text type
  other than plain is discarded instead of surfaced, matching firmware (group
  channels only carry plain text).

## [0.1.0]

Initial tagged release: wire protocol, crypto, codec, MQTT/serial transports, and
the base node/router foundation.
