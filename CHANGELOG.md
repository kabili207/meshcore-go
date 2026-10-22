# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions aim to
follow [Semantic Versioning](https://semver.org/). Pre-1.0, minor releases may
contain breaking changes; those are called out explicitly below.

## [Unreleased]

### Changed (breaking)

- **Removed APIs left over from the room server's legacy dispatch path.**
  - `Router.SendFloodReply` and `Router.SendFloodPathReply` are gone. Resolve
    the scope with `Router.ResolveReplyScope` and send with
    `SendFloodWithKey` / `SendFloodPathWithKey` (or their `Delayed` forms), as
    `BaseNode.SendReply` does.
  - `room.ServerConfig.PrivateKey` is gone. Only the removed packet-based login
    read it. `BaseNode` decrypts logins before the room server sees them.

  *Migration:* drop `PrivateKey` from a `room.ServerConfig` literal.
  `node.RoomConfig.PrivateKey` is unchanged.

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

- **Companion CLI** (firmware v1.18). The companion server answers
  `CMD_RUN_CLI_COMMAND` with `RESP_CODE_CLI_REPLY`. It supports `get/set name`,
  `board`, `ver`, `get/set tz.offset`, and the read-only `get radio`, `get freq`
  and `get tx`, with firmware's reply strings and the optional `NN|` prefix.
  Hardware commands such as `reboot` and radio setters reply `Unknown command`.
  A `TXT_TYPE_CLI_COMMAND` from a contact with the new `contact.FlagRemoteCLI`
  runs the same CLI and is answered over the mesh. From other contacts it still
  goes to the app. Also adds `cli.Ftoa` (firmware's float formatting),
  `codec.IsValidAdvertName`, and the contact telemetry permission flags.

- **Binary requests and unhandled responses.** `CompanionNode.SendBinaryReq`
  sends a request with a caller-supplied body and reports the reply as
  `event.BinaryResponse`. A response that matches no pending request, such as
  sensor push telemetry, is now reported as `event.UnhandledResponse` instead of
  being dropped. The companion server handles `CMD_SEND_BINARY_REQ` through the
  new `Config.SendBinaryReq` and pushes both events as
  `PUSH_CODE_BINARY_RESPONSE`, as firmware v1.18 does.

- **`TXT_TYPE_CLI_COMMAND` (3)**, the explicit CLI command text type from
  firmware v1.18, as `codec.TxtTypeCLICommand` and `serial.TxtTypeCLICommand`.
  Repeaters and room servers run it as an admin CLI command, exactly like type 1,
  and reply with type 1. Newer apps send it, and previously got no answer. The
  companion server accepts it from the app and sends it without ACK tracking.

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

### Changed

- **Firmware v1.18.0 is now the target.** The companion server reports
  `FIRMWARE_VER_CODE` 14 (was 13), which tells apps `CMD_RUN_CLI_COMMAND`
  exists. `cli.FirmwareVersion`, the `ver` reply for the repeater and room
  server and the companion's default version string, is `v1.18.0` (was
  `v1.16.0`). The companion's default build date comes from the new
  `cli.FirmwareBuildDate`. Apps use these values to decide which settings to
  offer, so they may now show 1.17 and 1.18 options. Ones we don't support
  reply as unknown keys. Set `Identity.FirmwareVersion` or the roles' `Version`
  to report something else.

- `acl.DefaultMaxClients` and `room.DefaultMaxClients` go from 20 to 32,
  matching firmware v1.18's `MAX_CLIENTS`.

- Repeaters no longer answer node discovery when forwarding is off, or when both
  advert intervals are 0. Firmware v1.18 treats the latter as a node that
  doesn't want to be found.

- **Transport code 0 is treated as un-scoped**, as in firmware v1.18. Such a
  TRANSPORT_FLOOD follows the wildcard region instead of being dropped as an
  unknown scope, counts against `MaxUnscopedFloodHops`, gets an un-scoped reply,
  and skips `ValidateTransportCode` (which also stops the validator from dropping
  the zero-hop `{0, 0}` contact share). Firmware still forwards code 0 when the
  wildcard denies flooding and doesn't cap it with `flood.max.unscoped`. We
  apply both limits, so code 0 can't be used to get un-scoped traffic past a
  repeater configured to block it.

- Repeaters default to `loop.detect minimal`, as in firmware v1.18. Firmware
  applies this to new installs only. Here it applies to any repeater that has no
  persisted `loop.detect`, since only changed settings are persisted. To keep the
  old behavior, load `loop.detect off` with `LoadConfig`.

### Fixed

- **A crafted packet could crash any node.** Decryption panicked when the
  ciphertext wasn't a whole number of AES blocks. A sender can produce a valid MAC
  for any length on an anonymous request (they pick the ephemeral key) or on a
  public channel, so one packet was enough. Such ciphertext is now rejected with
  `crypto.ErrUnalignedCiphertext`, matching firmware v1.18.

- **Stored paths with a different hash size were sent mislabeled.**
  `Router.SendDirect` encoded every path with this router's own
  `PathHashMode`. A path learned from a peer using 2- or 3-byte hashes went out
  with the wrong hop count and hash size (2 hops of 2 bytes became 4 hops of
  1 byte), so relays misrouted it. The new `Router.SendDirectPath` takes the
  path's encoded `path_len` byte and keeps its encoding, as firmware's
  `sendDirect` does. Replies, ACKs (multipart copies included), contact sends,
  DMs and companion requests all use it now. `SendDirect` is unchanged for raw
  paths that carry no encoding.

- **Regular contacts could take the anonymous contact slots.** Firmware keeps
  its `MAX_ANON_CONTACTS` slots reserved, so regular contacts only ever get
  `MAX_CONTACTS`. Ours let regular contacts grow into them. A repeater, which
  adds every advert it hears, could fill every slot on a busy mesh, after which
  a client login got no contact entry and its requests couldn't be decrypted.
  Regular contacts are now capped at `MaxContacts`.

- **An advert from an anonymous contact promoted it in place.** It is now
  replaced by a real contact allocated from the regular pool, as firmware does,
  keeping the anonymous entry's learned path (firmware drops it, but our
  repeaters and room servers route replies to logged-in clients through it). If
  the advert isn't auto-added, the anonymous entry is left alone instead of
  being promoted.

- **Anonymous requests got the wrong reply route.** The repeater now picks
  the route the way firmware's `chooseReplyRoute` does:
  - a flood request gets a path return
  - otherwise the reply goes direct along the path the request supplied, and
    a supplied path of zero hops now means zero-hop direct (it used to flood)
  - otherwise it goes along the stored path of a client on the access list,
    so a direct re-login is answered direct instead of flooded
  - otherwise it floods

  `BaseNode` also resolves the reply scope for anonymous requests, which it
  did only for addressed ones, so a flooded login reply is no longer sent
  unscoped.

- **Replies to zero-hop neighbors were flooded.** `ReplyContext.HasDirectPath`
  required path bytes, so a known zero-hop path (`DirectPathLen` 0) counted as
  no path. It now follows the field's documented contract, where only `0xFF`
  means unknown. Room keep-alives from zero-hop clients are now answered, as in
  firmware. Code that builds a `ReplyContext` by hand must set `DirectPathLen`
  to `contact.PathUnknown` for "no path". `BaseNode` already does.

- **Replies and ACKs went out with no delay.** Firmware holds them briefly so
  the requester's radio has switched back to receive, which matters whenever a
  transport bridges to RF. We now use the same delays:
  - Responses to requests and logins: 300ms (`router.ServerResponseDelay`).
    This is the default for anything sent with `BaseNode.SendReply`.
  - Repeater and remote companion CLI replies: 600ms (`cli.ReplyDelay`). The
    room server uses 300ms for CLI replies, as firmware does.
  - Text message ACKs: 200ms (`router.TxtAckDelay`), including an ACK carried
    in a path return. With multi-acks on, the multipart copies now go first,
    300ms apart (`router.MultiAckSpacing`), then the ACK, matching firmware's
    order. We used to send the ACK first.
  - `SendACK` and `SendACKPayload`, which answer requests such as a room
    keep-alive: 300ms.

  `event.ReplyContext.Delay` overrides the reply delay. The router gained
  `SendDirectDelayed`, `SendFloodScopedDelayed`, `SendFloodWithKeyDelayed` and
  `SendFloodPathWithKeyDelayed`. Delays only apply while the router is started.

- **A rejected login stayed pending.** Any response from a server with a pending
  login is now taken as the login reply and clears it, as in firmware. Before,
  only a successful login cleared it, so the rejection was dropped and later
  responses from that server were checked against the stale login.

- **Channel messages could be attributed to the wrong channel.** Group events
  carried only the 1-byte channel hash, which two channels share about 1 time in
  256. `event.GroupTextReceived` and `event.GroupDataReceived` now also carry
  `ChannelKey`, a copy of the key that decrypted the message. The companion
  server uses it to pick the channel slot, so a message on one channel no longer
  shows up under another channel with the same hash. Code that maps channels by
  `ChannelHash` should switch to `ChannelKey`.

- **Back-to-back CLI commands lost their replies.** `CompanionNode.SendText`
  stamped CLI messages with the plain clock, so two commands in the same second
  shared a timestamp and the admin node treated the second as a retry. CLI
  messages now use the unique clock, as firmware does.

- **The companion server now rejects text types firmware doesn't allow.**
  `CMD_SEND_TXT_MSG` with any type other than plain (0), CLI (1) or CLI command
  (3) returns `ERR_CODE_UNSUPPORTED_CMD`. Signed (2) used to be sent as is.

- **Deleting a channel from the app turned its slot into a null-key sink.** Apps
  delete a channel with `CMD_SET_CHANNEL`, an empty name and an all-zero secret.
  The companion server registered that zero key with the node, delivered traffic
  from nodes with an unset key to the app as if it belonged to the deleted slot,
  and accepted sends on it. It also never unregistered the slot's previous key,
  so deleted and overwritten channels kept decrypting. A slot now counts only
  when it has a name and a nonzero secret, the rule firmware v1.18 applies in
  `searchChannelsByHash`. `companion.Node` gained `RemoveChannel(key []byte)`;
  `*node.BaseNode` already implements it.

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
