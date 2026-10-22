# Upgrading meshcore-go to firmware v1.18.0

Analysis of upstream `meshcore-dev/MeshCore` between `companion-v1.17.1` (the
previous Go baseline) and `companion-v1.18.0` (`81dbae59`; the repeater and room
server tags point at the same commit), and what it means for this repo.

The local firmware checkout at `~/Projects/PlatformIO/MeshCore` is still at
`d9296435` (1.17.1). The 1.18.0 tags are fetched, so everything here was read from
the tags without touching the working tree.

## Headline: small wire additions, one crash bug

- `FIRMWARE_VER_CODE` goes from **13 to 14**. Apps use 14 to detect the new
  companion CLI command (item 5).
- No changes to packet header, payload types, path encoding, ACK layout or the
  region format. Everything that worked against 1.17 still works.
- Three wire additions, none of which break existing traffic:
  - `TXT_TYPE_CLI_COMMAND = 3`, a new text-message subtype.
  - `CMD_RUN_CLI_COMMAND = 66` / `RESP_CODE_CLI_REPLY = 29` in the companion
    frame protocol.
  - Sensor `REQ_TYPE_SUBSCRIBE = 0x08` / `REQ_TYPE_UNSUBSCRIBE = 0x09`, with
    unsolicited pushed telemetry.

174 non-merge commits landed. As in 1.17 most of them are boards, displays, radio
drivers, WiFi/BLE for RP2040 and power management.

A hardening fix upstream (item 1) exposed a remote crash in our crypto code. That
one should be fixed before anything else.

## Items that affect this repo

Ordered by priority.

> **Status:**
>
> | Item | Commit |
> |---|---|
> | 1. Unaligned ciphertext | `b4ca856` |
> | 2. Channel delete | `5cd8161` |
> | 3. Type 3 on repeater, room server and companion send | `6dc917a` |
> | 7. `MAX_CLIENTS` 32 | `1d716a1` |
> | 8. Discovery gates | `5abad07` |
> | 8. `loop.detect minimal` | `f512380` |
> | 4. Transport code 0 as unscoped (diverges, see item) | `51e37a6` |
> | 6. Binary requests and unhandled responses | `57845be` |
> | 5. Companion CLI and remote CLI | `aef1e9e` |
> | 5. Version code 14, `v1.18.0` | `5ffcd53` |
> | Optional: signed-message ACKs like plain ones | `c8467d0` |
> | Optional: CLI reply timestamps (repeater, room server) | `0ca5b84` |
> | Optional: login failures pushed to the app | `bcde811` |
> | Optional: `CMD_SEND_ANON_REQ` | `870229e` |
> | 8. Room server `set repeat on` deprecated | `7509844` |
>
> `6dc917a` also gives CLI messages unique timestamps, as firmware does.
> Without that, a second command in the same second was taken as a retry and
> got no reply.
>
> `57845be` also makes a rejected login clear its pending state, as firmware
> does. Replies and ACKs now use firmware's radio turnaround delays: 300ms
> for responses, 600ms for repeater and companion CLI replies, 200ms for text
> ACKs. Firmware also bumps a reply timestamp that
> equals the command's. The repeater and room server do now. The companion
> can't, since `SendDM` takes no timestamp (a TODO marks it).
>
> Still open: item 9 (no Go sensor role). The 1.17 leftovers are done (see
> the end of this file).

### 1. Unaligned ciphertext panics `macThenDecrypt` (critical)

Upstream `Utils::MACThenDecrypt` now rejects ciphertext whose length is not a
multiple of 16 (`9c9a2ba2`, `b74ba545`). In firmware the bug was a stack overflow.

Ours panics. `core/crypto/cipher.go:97` slices `plaintext[i:i+16]` with no
alignment check, so a valid MAC followed by 17 bytes of ciphertext gives
`slice bounds out of range [:32] with capacity 17`. Confirmed with a throwaway test.
Nothing in `core/` or `device/` calls `recover()`, so the process dies.

A valid MAC is easy to forge:

- **ANON_REQ:** the sender picks the ephemeral key, so they always know the shared
  secret. One crafted packet crashes any Go node that handles anonymous requests:
  repeater, room server or companion (`device/node/dispatch.go:204`,
  `device/room/login.go:37`).
- **GRP_TXT / GRP_DATA:** the Public channel key and every hashtag channel key are
  public (`device/node/dispatch.go:363`).
- **Random noise:** the MAC is only 2 bytes, so roughly 1 in 65536 corrupt packets
  per candidate key would trigger it with no attacker involved.

**Fix:** return an error from `macThenDecrypt` when
`len(ciphertext)%CipherBlockSize != 0`, plus a regression test. A few lines.

### 2. Deleting a channel registers the all-zero key

Upstream `searchChannelsByHash` now skips empty channel slots (`b7624204`). An
empty slot has an all-zero secret, so it matched traffic from nodes transmitting
with an unset key, and those messages were delivered as if they belonged to that
slot.

Our `BaseNode` only holds keys that were explicitly added, so it doesn't have the
empty-slot problem itself. The companion frame server does, from the other
direction. Apps delete a channel by sending `CMD_SET_CHANNEL` with an empty name
and an all-zero secret (upstream `docs/companion_protocol.md`, "Delete Channel").
`setChannel` (`device/companion/companion.go:577`) then:

- calls `s.node.AddChannel(secret)` with the zero key, which creates the exact sink
  upstream just closed, and
- never calls `RemoveChannel` for the slot's previous key, so a deleted (or
  overwritten) channel keeps decrypting.

`channelIndexForHash` (`:611`) also matches slots by secret alone, ignoring an
empty name.

**Fix:** in `setChannel`, remove the old key, and skip `AddChannel` when the name
is empty or the secret is all zeros. Skip empty-name slots in
`channelIndexForHash`. About 15 lines plus tests.

`MAX_SEARCH_RESULTS` went from 8 to 24. `channelKeys` has no cap, so that change
doesn't apply.

### 3. `TXT_TYPE_CLI_COMMAND = 3`

Type 1 (`TXT_TYPE_CLI_DATA`) is now documented as "a CLI command or reply", and
type 3 means "a CLI command, explicitly". Newer apps and companions can send type
3 to admin nodes.

Firmware behavior:

- **Repeater** (`simple_repeater/MyMesh.cpp:707`) and **room server** treat 3 the
  same as 1: admin only, no ACK, replay-protected by timestamp, reply sent as type
  1 after 600ms.
- **Companion** (`BaseChatMesh::onPeerDataRecv`): if the sending contact has the
  new remote-CLI flag (`0x10`), the command runs through the companion's local CLI
  (item 5) and the reply goes back as type 1, direct if a path is known, otherwise
  a scoped flood. Without the flag the message goes to the app as an ordinary
  `CONTACT_MSG_RECV` with txt_type 3.
- **Companion send:** `CMD_SEND_TXT_MSG` accepts txt_type 3 and handles it like
  type 1 (node clock, no ACK tracking). Any type other than 0, 1 or 3 gets
  `ERR_CODE_UNSUPPORTED_CMD`.
- The flood path-return that used to follow a received type 1 message is gone. We
  never sent it, so nothing to remove.
- `ContactInfo` gained flag helpers: favorite `0x01`, telemetry base `0x02`,
  location `0x04`, environment `0x08`, remote CLI `0x10`.

What we do today:

- `core/codec/payload.go:71-74` and `core/codec/serial/build.go:16-20` define only
  types 0 to 2, and `TxtTypeName` doesn't know 3.
- `device/node/repeater_cli.go:22` and `device/room/handlers.go:144-182` ignore
  type 3. **A newer app sending CLI commands to a Go repeater or room server gets
  no answer.**
- The companion server (`companion.go:641`) sends anything other than type 1
  through the ACK-tracked path, and doesn't reject unsupported types.
- `device/contact/contact.go` defines only `FlagFavorite`.
- Receiving type 3 on a companion already reaches the app as `CONTACT_MSG_RECV`,
  which matches firmware when the remote-CLI flag is off.

**Fix:** add the constant, accept it on the repeater and room server, treat it
like type 1 on companion send, and add the contact flag constants. About 40 lines.
The remote-execute path on companions depends on item 5.

Pre-existing gap found while checking this: the firmware repeater still accepts
**type 0 (plain) from an admin as legacy CLI**, and ACKs it. Ours ignores it.

### 4. Transport code 0 is treated as unscoped

`RegionMap::findMatch` now returns the wildcard region when
`transport_codes[0] == 0` (`01f9293b`, PR #3568). `calcTransportCode` never
produces 0, so before this change such a packet matched nothing and was dropped.

**What sends it.** Nothing, in normal operation:

- Codes `0000` and `FFFF` have been reserved since regions were introduced
  (`963290ea`, November 2025), so no firmware hashes to 0.
- The companion has no way to choose code 0 for a flood.
- Neither the agessaman observer fork nor EastMesh sends it.
- meshcore.js only parses packets. meshcore_py and meshcore-cli pass
  `send_raw_packet` bytes through from the user.

The one existing use of `{0, 0}` is the companion's "share contact" advert
(`shareContactZeroHop`, `7755400a`). It's a zero-hop TRANSPORT_DIRECT packet, and
`findMatch` is only called for TRANSPORT_FLOOD. So in practice code 0 on a flood
comes from injected or third-party packets, or from some future protocol use.
PR #3568 has no description or discussion. The "home region" REVISIT notes on
`transport_codes[1]` hint at a sender wanting to fill in `codes[1]` while staying
unscoped, but that's a guess.

**Where firmware is inconsistent.** The PR title says code 0 is "the same as
un-scoped", and region matching and the reply scope do treat it that way. But
`findMatch` returns the wildcard *before* the mask check, so a code 0 flood is
forwarded even when the wildcard denies flooding. And `isFloodHopLimitExceeded`
applies `flood.max.unscoped` only to `ROUTE_TYPE_FLOOD`. A plain flood is subject
to both limits, so code 0 lets anyone get unscoped traffic past a repeater set
up to block it.

**What we do.** We treat code 0 as fully unscoped: wildcard flags apply, the
unscoped hop cap applies, replies go out unscoped, and `ValidateTransportCode`
skips it. The rationale and a REVISIT note live on `isUnscoped` in
`device/router/transport.go`. This deliberately diverges from firmware's
forwarding behavior.

Pre-existing divergence: when the wildcard denies flooding, firmware sets
`recv_pkt_region = NULL` for a plain FLOOD, so its reply uses the default scope.
We always reply to a plain FLOOD unscoped.

### 5. Companion CLI: `CMD_RUN_CLI_COMMAND` (66) and `RESP_CODE_CLI_REPLY` (29)

Companions now have a text CLI reachable from the app, from USB, and remotely via
type 3 messages (item 3).

- **Request:** `[0x42][ASCII command]`, at least 3 bytes, no NUL required. Leading
  spaces are skipped. An optional 3-character prefix `xx|` is stripped and echoed
  at the start of the reply.
- **Reply:** `[0x1D][reply text]`, no NUL, up to about 165 bytes. An unknown command
  replies `Unknown command`. There is no OK or ERR frame.
- **Commands:** the radio set from the new shared `CommonRadioPrefs` (`radio`,
  `af`, `tx`, `txdelay`, `path.hash.mode`, `multi.acks` and others), `reboot`,
  `poweroff`/`shutdown`, `get/set name` (rejects any of `[]\:,?*`), `set pin`,
  `board`, `ver`, `get/set tz.offset` (-12 to +14), and WiFi keys on WiFi builds.

We don't define opcode 66, so it falls through to `ERR_CODE_UNSUPPORTED_CMD`.
`device/cli` exists but only the room server and repeater mount it.

**Fix:** add the two constants and a small companion CLI on `device/cli`: name,
`ver`, `board`, `tz.offset`, `path.hash.mode`, `multi.acks`, read-only radio
getters, and `Unknown command` for everything else. Wire it to type 3 messages
from contacts with the remote-CLI flag. Then bump `CompanionFirmwareVerCode` to 14
(`core/codec/serial/build.go:25`, test at `payload_test.go:60`). About 150 to 250
lines.

**Do the version bump last.** Reporting 14 tells apps this command exists.

### 6. Unhandled responses go to the app as `PUSH_CODE_BINARY_RESPONSE`

`onContactResponse` used to drop a `RESPONSE` that matched no pending request. It
now pushes it to the app as `[0x8C][0x00][tag u32 LE][body]`, the same layout as a
matched binary response (`b204f9a1`). The use case is sensor push telemetry
(item 9), which carries a client-chosen tag that never matches a pending request.

Ours drops it: `device/node/companion_login.go:119-127` tries the login, telemetry
and status handlers and discards anything else. `PushCodeBinaryResponse` is
defined (`core/codec/serial/protocol.go:119`) but never built.

**Fix:** have the handlers report whether they consumed the response, emit an
event for the rest, and push it from the companion server. About 50 lines. Doing
`CmdSendBinaryReq` (already a listed gap) at the same time makes sense, since it
uses the same encoder.

### 7. `MAX_CLIENTS` 20 to 32

The firmware ACL default is now 32 for all roles. Ours is 20 in
`device/acl/store_mem.go:10` and `device/room/clientstore_mem.go:13`, and the doc
comment at `device/node/repeater.go:39` says 20. Trivial.

### 8. Smaller repeater and room server changes

- **Hidden nodes ignore DISCOVER** (`f19733e4`). The repeater no longer answers
  `NODE_DISCOVER_REQ` when both advert intervals are 0. Ours checks only the rate
  limiter (`device/node/repeater_discover.go:41`). Firmware also skips it when
  forwarding is disabled, which we don't check either. Two lines.
- **Repeater `loop.detect` defaults to `minimal`** for new installs (`2db4b406`).
  Ours defaults to off: `NewRepeater` never sets `RouterConfig.LoopDetect`. Room
  server and sensor stay off. One line, plus optionally a config field.
- **Room server `set repeat on` is deprecated** (`8579c667`, `481f72ca`). It now
  replies `ERR - repeat now deprecated`. We have no `repeat` key, so we reply
  `??: repeat`, which is fine. Optional.
- **CLI validation** (`f722794e`, `0c3fe356`): `set af` takes 0 to 9,
  `agc.reset.interval` is clamped to 0 to 1020, and most radio `get` forms now
  need an exact match. All radio keys, so N/A.

Pre-existing mismatch found here: the room server's `radio` key
(`device/room/cli.go:157`) returns the radio model, but firmware's `get radio`
returns `freq,bw,sf,cr`.

### 9. Sensor subscribe and push telemetry (no Go sensor role)

We have no sensor node, so this is wire documentation for later and for
client-side support (item 6).

The ACL entry gained a `sensor` block: expiry, `push_tag`, `scope_region_id`, and
`min_deltas` / `prev_telem` (14 bytes each, LPP encoded). Both requests need at
least the read-only role. Payloads follow the usual `[timestamp 4][req_type 1]`.

- **`REQ_TYPE_SUBSCRIBE` (0x08):**
  - **Request:** `[push_tag u32][timeout_secs u16][reserved u8][min_deltas_len u8][min_deltas]`.
    `min_deltas_len` must be 3 to 14 and is mandatory (`df82dc23`). The default
    timeout is 30 minutes, max about 18 hours.
  - **OK reply:** `[tag 4][timeout_secs u16][reserved 2][scope name, ASCII, no NUL]`.
    Since `3819a0bd` it returns seconds, not an absolute timestamp.
  - **Error reply:** `[tag 4][4 zero bytes]`.
  - The scope is the request's region if it arrived scoped, otherwise the node's
    default scope.
- **`REQ_TYPE_UNSUBSCRIBE` (0x09):** no body. Reply is `[tag 4][8 zero bytes][2 random bytes]`.
- **Push:** on each sensor read, for each live subscriber whose specified channels
  moved by more than their min delta, an unsolicited `RESPONSE`
  `[push_tag 4][timestamp 4][LPP telemetry]`, sent direct if a path is known,
  otherwise flooded in the subscription's scope.

The sensor also gained a region map, `region load/save`, default and reply scopes
(`b4e37044`), scoped adverts and ACKs, and MCU temperature in telemetry.

## Explicitly not actionable

- **Direct ACK forwarding delay** (`6df5aaed`). Forwarded direct ACKs now wait
  `getDirectRetransmitDelay()` and extra ACKs are spaced 300ms apart. We forward with
  zero delay (`router.go:616`) and never send the extra multi-ACK copies on
  forward. Both fall under the airtime/CSMA gap in `FEATURE_PARITY.md`.
- **`CommonRadioPrefs` refactor.** Radio CLI moved into its own helper that runs
  before the rest of CommonCLI. Reply strings are unchanged, and we implement only
  `path.hash.mode` and `multi.acks` from it.
- **`CMD_SEND_RAW_DATA` (25) path fix.** Byte 1 is now an encoded path length (hash
  size in the top 2 bits, hop count in the low 6), validated with
  `isValidPathLen`. Not dispatched in Go; use the encoded form when it is.
- **`CMD_SEND_CHANNEL_DATA` (62) limit** is now `MAX_GROUP_DATA_LENGTH` (165), and
  oversize gets `ERR_ILLEGAL_ARG`. Not dispatched; when it is, use
  `codec.MaxGroupDataLength` rather than `serial.MaxChannelDataLength` (167).
- **`AdvertDataParser::isValidName`** is only used for CLI `set name` validation,
  not advert parsing.
- **Companion node discovery.** `CTL_TYPE_NODE_DISCOVER_*` are now defined in the
  companion, but only the on-device UI uses them. The companion still doesn't
  answer discovers.
- **Nelos `0x0140`** GroupData type allocation. Docs only.
- **Prefs storage** (`DynamicConfigSerializer`, `custom` section, digits in keys),
  the `MyMesh::Listener` UI refactor, `StaticPoolPacketManager` null guards,
  power-management virtuals, WiFi/BLE on RP2040, LR1121, displays, boards.
  Firmware only.

## Leftovers from 1.17

Done:

- **`REPLY_ROUTE_DIRECT_OUT_PATH` for anon requests** (`1d18737`). The
  repeater picks the reply route like `chooseReplyRoute`. That needed two
  fixes. `ReplyContext.HasDirectPath` treated a zero-hop path as no path, and
  `BaseNode` didn't resolve a reply scope for anonymous requests.
- **Clearing the anon slot when a real advert arrives** (`5e6988a`). Unlike
  firmware, the learned path carries over, and the slot is left alone when the
  advert isn't added. The work also turned up `3f2d561`: regular contacts could
  take the reserved anon slots, which firmware never allows.

Still deliberate: `truncateName` in `device/router/region.go` stays byte-wise.

## Suggested order

1. Item 1 (crypto panic). Small, and it's a remote crash.
2. Item 2 (channel delete).
3. Item 3 (type 3 on repeater and room), item 7 (`MAX_CLIENTS`), item 8 gates and
   defaults.
4. Item 4 (transport code 0), after deciding on the wildcard-deny question.
5. Item 6 (binary response push), together with `CmdSendBinaryReq`.
6. Item 5 (companion CLI), then the version bump to 14.
7. The 1.17 leftovers.
