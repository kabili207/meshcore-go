# Upgrading meshcore-go to firmware v1.17.1

Analysis of upstream `meshcore-dev/MeshCore` between `companion-v1.16.0` (the current
Go baseline) and `companion-v1.17.1`, and what it means for this repo.

Local firmware checkout: `~/Projects/PlatformIO/MeshCore`, now at `d9296435`
(`* version 1.17.1`).

## Headline: the wire protocol did not change

- `FIRMWARE_VER_CODE` is still **13**, same as v1.16.0.
- No new or changed mesh payload types. `Packet.h`'s only diff is a comment typo
  (`SNI` to `SNR`).
- No new or renumbered companion serial `CMD_*` constants. `CMD_SEND_RAW_PACKET = 65`
  is still the maximum, and it was already there in v1.16.0 (`FEATURE_PARITY.md`
  already tracks it).
- `MAX_FRAME_SIZE`, packet hash, ACK layout, region format: all unchanged.

So nothing here breaks compatibility. 367 commits landed, but the large majority are
display drivers, board/pin fixes, and nRF52 hardware crypto. The crypto work
(`USE_CC310_HW_CRYPTO` in `Utils.cpp` / `Identity.cpp`) is hardware acceleration
behind an ifdef and produces byte-identical output.

The v1.17.0 to v1.17.1 patch is 47 commits, essentially all board pin corrections
plus one routing fix (below).

## Items that actually affect this repo

Five findings, ordered by how much they matter here.

> **Status:** items 1, 2, and 4 are done (commits `c9ce9da`, `8e1f0fc`, `3178c50`).
> Item 3 (scoped reply routing) and item 5 (anon-slot review) are still open.

### 1. Dedup split into `wasSeen()` / `markSeen()` — we already did this

Upstream split `MeshTables::hasSeen()` (which both tested and inserted) into separate
`wasSeen()` and `markSeen()` calls across every receive path in `Mesh.cpp`, and
reworked `SimpleMeshTables` to match.

This is the same problem commit `a738607` fixed here ("capture before dedup"), arrived
at independently. Our fix moved the observer hook ahead of the dedup gate; upstream
instead made the check non-mutating so the mark can be placed deliberately. Same
outcome for observers.

Our `PacketDeduplicator.HasSeen()` (`core/dedupe/dedupe.go:58`) is still the combined
check-and-mark, with send-side call sites discarding the return value to use it as a
bare mark. That works, but it now reads differently from firmware and the "call it and
ignore the result" idiom is easy to misread.

**Done** (`3178c50`). Added `WasSeen` (pure query) and `MarkSeen` (record only), and
converted the eight send-side mark-only call sites. The receive gate keeps the combined
`HasSeen`: it needs check-and-record as one step, and the whole receive path runs under
`recvMu`, so it is equivalent to firmware's pair without a second lock acquisition.
No behavior change; race detector clean.

### 2. `path_len` validation on the inner PATH payload — real gap

`Mesh.cpp` now rejects a bad `path_len` on the *decrypted* `PAYLOAD_TYPE_PATH` content:

```cpp
uint8_t path_len = data[k++];
if (!Packet::isValidPathLen(path_len)) {
  break;   // reject bad encoding
}
```

`Packet::isValidPathLen` (`src/Packet.cpp:13`) rejects reserved hash mode 3
(`hash_size == 4`) and enforces `hash_count * hash_size <= MAX_PATH_SIZE` (64).

We validate this on the **outer** packet header (`core/codec/packet.go:229-241`,
including `ErrReservedPathMode`) but **not** on the inner decrypted PATH content.
`ParsePathContent` (`core/codec/payload.go:465`) only bounds-checks against the
buffer, so a `path_len` of `0xFF` (mode 3, 63 hops, 252 bytes) is accepted whenever
the decrypted blob is long enough — and decrypted content can exceed 64 bytes since
`MaxPacketPayload` is 184.

The unvalidated wire byte then propagates: it is stored verbatim as a contact's
`OutPathLen` with the raw bytes as `OutPath` (`device/contact/helpers.go:180`), reached
from `device/node/dispatch.go:303` and `device/room/dispatch.go:62`, mirrored into the
room client store, and persisted. A peer can poison a stored path this way.

`parseAnonReplyPath` (`device/node/repeater_anon.go:98`) has the same shape: a
client-supplied `{path_len}{path}` with only a buffer-length check, copied into
`rc.DirectPathLen` at `:63`.

**Done** (`c9ce9da`). Added `PathInfo.IsValid` mirroring `isValidPathLen` and called it
at both sites. Confirmed the gap was real before fixing: without the check, both a
reserved-mode and a 189-byte path parsed successfully (`error = <nil>`).

### 3. Scoped reply routing (PR #3106) — new firmware behavior we lack

New `src/helpers/RoutingPolicy.h` factors three decisions into testable helpers, used
by both the repeater and room server:

- `isFloodHopLimitExceeded(pkt, flood_max, flood_max_unscoped, flood_max_advert)`
- `chooseReplyRoute(inbound_is_flood, have_supplied_path, have_out_path)`
- `chooseReplyScope(request_scope_known, request_was_unscoped_flood, default_scope_known)`

Two of these are new behavior rather than refactoring:

**Reply scope.** Firmware now mirrors the request's transport scope onto a flooded
reply, falling back to a configured `default_scope`, and only sends unscoped when the
requester did. The motivating bug: an unscoped reply is dropped at hop 0 by any
repeater running `flood.max.unscoped=0`.

We have no equivalent. `Config.SendScope` (`device/router/router.go:129`) is a single
global; the inbound packet's `TransportCodes` are validated on receive
(`router.go:422`) but never read back to scope the reply, and there is no default-scope
fallback. Nothing in `device/room/respond.go` or `device/node/base.go` consults
`origPkt.TransportCodes`.

**Reply route.** `chooseReplyRoute` gives a DIRECT login the option of replying via a
stored `out_path`, which the repeater's anon path previously could not do. Our
precedence (`device/node/base.go:253`) is flood-arrival wins, then supplied path, then
stored path, then flood — which matches `chooseReplyRoute` for the flood and
supplied-path cases. The gap is the `REPLY_ROUTE_DIRECT_OUT_PATH` case for anon
requests.

**Action:** the reply-scope work is the larger of the two and the more visible on a
real mesh with scoped regions. Needs a `DefaultScope` config, plumbing the request's
resolved region into the reply context, and a `chooseReplyScope` equivalent. Worth
scheduling, but it is a design change, not a patch.

Note our hop-limit semantics already match: firmware `hops >= flood_max` versus our
`hopCount + 1 > MaxFloodHops` are equivalent, and the check ordering is the same. The
`docs/cli_commands.md` note about `flood.max.unscoped` defaulting to `0xFF` ("tracks
flood.max until set") is not implemented — both roles still initialize it to 64, same
as our `DefaultMaxUnscopedFloodHops`.

### 4. UTF-8 aware advert name truncation

`AdvertDataBuilder::encodeTo` now truncates the node name at a valid UTF-8 boundary via
the new `mesh::validUtf8PrefixLength` (`src/helpers/UTF8Helpers.h`), instead of copying
bytes until the buffer fills.

Ours truncates the assembled buffer with a raw byte slice
(`core/codec/builder.go:120-126`, `data = data[:MaxAdvertAppDataSize]`) and can split a
rune. The name sits at the tail of the buffer, so the budget shrinks to 19 bytes with
GPS plus both feature fields — a mid-rune cut is reachable with emoji or non-Latin
names.

This is cosmetic on the wire (both sides sign whatever bytes result, so signatures
still verify) but a node with an emoji name would advertise a mangled trailing byte and
render as a replacement character in clients. Firmware documents the new budget as
"23 bytes when location is included and 31 bytes otherwise."

**Done** (`8e1f0fc`). The name is now truncated to the remaining budget at a rune
boundary before the buffer is sized, and `FlagHasName` is only set when something
survives (matching firmware's `name_len > 0` guard). Verified the resulting budgets are
31 bytes for a name alone and 23 with location, exactly as the firmware docs state.

`truncateName` in `device/router/region.go:385` was checked and deliberately left
alone. Firmware copies region names with a byte-wise `StrHelper::strncpy`
(`RegionMap.cpp:167`) and did *not* get the UTF-8 treatment in v1.17 — only advert
names did. Making the Go side rune-aware would diverge from firmware in a fixed-width
binary field that has to round-trip through the `/regions2` format.

### 5. `MAX_ANON_CONTACTS` — we model this differently

Firmware reserved the first 8 slots of the contacts array for transient ANON_REQ
contacts (`MAX_ANON_CONTACTS = 8`), added `getTotalContactSlots()` versus
`getNumContacts()`, and made `ContactsIterator` start past the reserved region.
`onAdvertRecv` now clears a temp anon slot when a real advert arrives for that key.

We already have `DefaultMaxAnonContacts = 8` (`device/contact/manager.go:12`), but
separate the pools **by node type at eviction time** rather than by array index —
`IsTransient()` tests `Type == NodeTypeNone`. Since our persisted format is per-contact
JSON records, slot ordering does not matter for compatibility.

One behavioral difference is worth a look: our growth is gated by `MaxContacts` alone
(`manager.go:333`), so the anon headroom is never populated by the append path. Once
`len == MaxContacts`, a transient add must evict an existing transient and returns nil
if there is none, rather than using one of the 8 reserved slots.

**Action:** verify that nil-return path is intentional. Consider adopting the
firmware's "clear the anon slot when a real advert arrives for that pubkey" behavior,
which we may not do today. Low priority.

## Explicitly not actionable

- **`ConfigSerializer` / `NodePrefs` rewrite.** Prefs moved from a packed binary struct
  to a nested JSON-ish serializer with named keys. This is on-device flash storage, not
  wire format, and has no Go counterpart.
- **`radio.fem.rxgain` / `radio.fem.txgain` CLI keys and the `MeshCore.h` FEM virtuals.**
  Hardware PA/LNA control; N/A for a transport-attached node. The v1.17.1 patch even
  comments out their load/save until they can be set.
- **`cad` CLI key, `getCADEnabled()`.** Radio hardware; N/A. Still part of the broader
  "no airtime/duty-cycle/CSMA anywhere" systemic gap already in `FEATURE_PARITY.md`.
- **MCU temperature in telemetry.** Firmware now adds `board.getMCUTemperature()` to
  self-telemetry. Our `telemetry.Provider` is pluggable and the host app populates it,
  so this is an app-level choice, not a library gap.
- **Ethernet interfaces, `MultiSerialInterface`, display drivers, board pin fixes,
  nRF52 CC310 crypto.** All firmware-only.
- **`poweroff`/`shutdown` CLI commands.** Hardware; N/A.

## Remaining work

Done so far, each in its own commit:

1. Inner-PATH `path_len` validation — `c9ce9da`
2. UTF-8 advert name truncation — `8e1f0fc`
3. Dedup `WasSeen`/`MarkSeen` split — `3178c50`

Still open:

- **Scoped reply routing (item 3).** The real 1.17 feature gap, and the one most
  visible on a mesh with scoped regions. Needs a `DefaultScope` config, the request's
  resolved region plumbed into the reply context, and a `chooseReplyScope` equivalent.
  Deserves its own design pass rather than a patch.
- **Anon contact slots (item 5).** Verify the `allocateSlot` nil-return is intentional
  and decide whether to adopt firmware's "clear the anon slot when a real advert
  arrives" behavior. Low priority.

Note the pre-existing `transport/udp` test failure (`TestProcessDatagram_Malformed`
panics on a nil logger). It is unrelated to any of this work and was failing before
these changes; the rest of the suite is green.

## Unrelated: firmware checkout state

The fast-forward to `d9296435` succeeded. Your local modification to
`variants/heltec_v3/platformio.ini` (enabling `MESH_PACKET_LOGGING`) was preserved.

Upstream **deleted** `.vscode/extensions.json`, which you had also modified — your only
change was re-adding a comment header, no content difference. That deletion is still
unresolved in the working tree (`DU` state) because `git rm` was blocked by a
permission prompt. Resolve with:

```
git rm .vscode/extensions.json
git stash drop        # the pre-merge stash, no longer needed
```
