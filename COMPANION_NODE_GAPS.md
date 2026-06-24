# meshcore-go: Companion/Chat Node Implementation Gaps

This document catalogs everything that had to be built from scratch, worked around,
or manually reimplemented when building a companion node (NodeTypeChat) using
meshcore-go. The library currently provides good support for room servers
(`device/room`) but has no equivalent for companion/chat nodes that exchange DMs.

The goal is to make building a companion node as straightforward as the room server,
ideally with a `device/chat` or `device/companion` package.

---

## 1. No Application-Level ACK Sending

**Problem:** The library does not automatically send ACKs for received TXT_MSG
packets. The firmware retransmits messages until it receives an ACK, so without
explicit ACK handling, every message triggers 3+ retransmissions.

**What we had to build:**
- Compute the ACK hash: trim AES-128 ECB padding from the decrypted plaintext
  (matching firmware's `strlen()` behavior), then call `crypto.ComputeAckHash()`
- Build an ACK packet manually with `codec.BuildAckPayload()`
- Send it via `router.SendFlood()` (or `SendDirect()` when a path is known)

**Why this matters:** ACK computation requires understanding the padding semantics
of AES-128 ECB block encryption. The decrypted plaintext contains trailing zero
bytes from block padding, but the firmware computes ACK hashes using
`header(5) + strlen(text)` — only up to the first null byte. If you hash the full
padded plaintext, the ACK hash won't match and the firmware keeps retransmitting.

**Reference:** The room server handles this in `dispatch.go` with `trimTxtMsgContent()`
and `sendACK()`. We had to reimplement both in the BBS handler.

**Suggested fix:** A companion node helper should automatically ACK received
TxtTypePlain messages after successful decryption. The `trimTxtMsgPlaintext` +
`ComputeAckHash` + send pattern should be encapsulated so consumers don't need to
know about ECB padding.

**v1.16 update:** Plain text-message ACKs are now 6 bytes, not 4. The first 4 bytes
are the same hash; byte 4 is the sender's tail attempt byte (the byte after the
message text, present when the send attempt exceeds 3, else 0) and byte 5 is random.
The sender still matches only the leading 4 bytes; the extra two make the ACK's
packet hash unique now that ACKs dedup through the normal packet-hash table instead
of a separate checksum table. Use `codec.BuildAckPayloadExt(hash, attempt, rnd)` for
plain text. Signed messages and keepalives keep the 4-byte `codec.BuildAckPayload`.
The room server's `buildPlainTextAck` in `dispatch.go` is the reference.

---

## 2. No Companion Node Packet Handler

**Problem:** The library provides `room.Server` with a complete `HandlePacket` →
dispatch → decrypt → route pipeline, but there's no equivalent for companion/chat
nodes. We had to rebuild the entire receive path from scratch.

**What we had to build:**

1. **Packet handler** registered via `router.SetPacketHandler()` that switches on
   `pkt.PayloadType()` for ADVERT, TXT_MSG, and ACK
2. **Advert processing** — parse, verify signature, extract identity, add/update
   contact. The library's `contact.ProcessAdvert()` exists but doesn't handle
   flood path extraction from the packet (see item 4)
3. **Addressed payload decryption** — `ParseAddressedPayload()` → filter by
   `DestHash` → `SearchByHash(SrcHash)` → try-decrypt loop with each candidate's
   shared secret
4. **Text message parsing** — `ParseTxtMsgContent()` on the decrypted plaintext
5. **ACK computation and sending** (see item 1)

**Reference:** The room server's `handleAddressed()` in `dispatch.go` does steps
2-5 as an integrated pipeline. For a companion node, this same pattern is needed
but without the room server's client/guest access control.

**Suggested fix:** Provide a `device/companion` or `device/chat` package with a
handler that accepts a callback for decrypted messages:

```go
type MessageHandler func(from core.MeshCoreID, contact *contact.ContactInfo, msg *codec.TxtMsgContent)

node := companion.New(companion.Config{
    Router:   r,
    Contacts: contacts,
    PrivKey:  privKey,
    OnMessage: func(from core.MeshCoreID, ct *contact.ContactInfo, msg *codec.TxtMsgContent) {
        // Application logic — message already decrypted and ACK already sent
    },
})
r.SetPacketHandler(node.HandlePacket)
```

---

## 3. No DM Sending Helper

**Problem:** Sending an encrypted DM requires manually orchestrating 6+ steps
across 4 packages. The room server has `sendEncryptedResponse()` but it's
private to the `room` package, uses RESPONSE packet type (not TXT_MSG), and
includes PATH return logic that's room-server-specific.

**What we had to build:**
1. `contacts.GetSharedSecret(to)` — look up shared secret
2. `codec.BuildTxtMsgContent(timestamp, TxtTypePlain, 0, message, nil)` — build
   plaintext with header
3. `crypto.EncryptAddressedWithSecret(plaintext, secret)` — encrypt
4. `codec.SplitMAC(encrypted)` — separate MAC from ciphertext
5. `codec.BuildAddressedPayload(destHash, srcHash, mac, ciphertext)` — build
   addressed envelope
6. Construct `codec.Packet` with correct header bits (`PayloadTypeTxtMsg << PHTypeShift`)
7. Route via `router.SendFlood()` or `router.SendDirect()`

**Subtlety — TxtTypePlain vs TxtTypeCLI:** Companion/chat nodes MUST use
`TxtTypePlain` for DMs. Using `TxtTypeCLI` causes the firmware to invoke
`onCommandDataRecv()` instead of `onMessageRecv()`, which silently drops the
message in chat apps. This distinction is not documented and was discovered
through firmware source analysis.

**Suggested fix:** Provide a `SendDM(to MeshCoreID, message string) error` method
on the companion node that handles the entire encrypt-build-send pipeline.
The method should automatically choose direct vs flood based on the contact's
`HasDirectPath()`.

---

## 4. No Flood Path Reversal for Contacts

**Problem:** When a flood packet arrives, `pkt.Path` contains relay hashes in
sender → receiver order. To reply via direct routing, the path must be reversed.
The room server has `reverseFloodPath()` in `respond.go`, but this is private
to the `room` package.

Additionally, `contact.ProcessAdvert()` does NOT extract or store the flood path
from the packet. It only processes the advert payload itself. Path information
from adverts must be extracted and stored separately by the caller.

**What we had to build:**
- Our own `reverseFloodPath()` identical to the room server's
- Manual path extraction and reversal in both `handleAdvert()` and
  `handleTextMessage()` before storing to `contact.OutPath`

**Suggested fix:**
- Export `reverseFloodPath` (or equivalent) as a utility function
- Have `ProcessAdvert` accept the packet (or path + pathLen) so it can
  store the reversed flood path on the contact automatically
- Alternatively, add a `contact.UpdatePathFromFlood(pkt)` helper

---

## 5. No Integrated Contact Path Management

**Problem:** The contact manager stores `OutPath` and `OutPathLen`, but there's
no helper to update a contact's path from an incoming packet. The room server
gets path updates from PATH packets (via `contact.ProcessPath()`), but companion
nodes receive path information embedded in flood packets.

**What we had to build:**
- In `handleAdvert()`: extract `pkt.Path`, reverse it, store on new/updated contact
- In `handleTextMessage()`: same path extraction after successful decryption, then
  `contacts.UpdateContact()` to persist it

**The room server's approach:** PATH packets are separate encrypted messages that
carry the reversed path. The firmware sends these as a response to flood messages.
Room servers process them via `contact.ProcessPath()` which handles the update.

**For companion nodes:** Flood path from incoming packets is the primary path source.
PATH packets may also arrive but require the same decrypt-then-process pipeline.

**Suggested fix:** The companion node handler should automatically update contact
paths from incoming flood packets after successful decryption.

---

## 6. Direct Routing Does Not Work (Unresolved)

**Problem:** `router.SendDirect()` with correct reversed paths does not reliably
deliver packets on MQTT-bridged networks, while `router.SendFlood()` works fine.

**Symptoms:** ACKs and DMs sent via `SendDirect` with `path_len=1` never reach
the destination. The same packets sent via `SendFlood` arrive immediately.

**What we tried:**
- Verified path reversal is correct (matches room server's `reverseFloodPath`)
- Verified `SendDirect` sets `RouteTypeDirect` header bits and path bytes correctly
- Verified the MQTT transport serializes direct packets identically to flood packets
  (same `WriteTo()` → base64 → publish path)
- Verified the Python MQTT bridge preserves packets end-to-end (no modification)
- Verified the firmware's direct routing logic (`handleDirectForward`) correctly
  matches `Path[0]` against relay hashes and forwards

**Analysis:** On paper, the packet flow should work:
1. BBS sends direct packet via MQTT
2. Bridge writes to serial → firmware repeater receives
3. Repeater checks `Path[0]` matches its hash → strips self → forwards over RF
4. Destination receives direct packet with `PathLen=0`

The room server's `sendEncryptedResponse` and `sendACK` both use `SendDirect` when
a direct path is available. If direct routing is working for room servers on the
same network, the issue may be specific to how the companion node's router is
configured (e.g., `ForwardPackets: false` affecting outbound direct routing).

**Current workaround:** Always use `SendFlood()` for both ACKs and DMs.

**Suggested investigation:** Test `SendDirect` from the room server library on the
same MQTT-bridged network to confirm it works there. If it does, diff the router
configuration and packet construction. Add debug logging at the firmware bridge
level to trace whether direct packets arrive and are forwarded or dropped.

---

## 7. Header Construction Requires Manual Bit Shifting

**Problem:** Constructing packet headers requires knowing the bit layout:
`codec.PayloadTypeTxtMsg << codec.PHTypeShift`. This is error-prone and
undocumented.

**Example from our code:**
```go
pkt := &codec.Packet{
    Header:  codec.PayloadTypeTxtMsg << codec.PHTypeShift,
    Payload: payload,
}
```

**Suggested fix:** Provide a constructor or helper:
```go
pkt := codec.NewPacket(codec.PayloadTypeTxtMsg, payload)
// or
pkt.SetPayloadType(codec.PayloadTypeTxtMsg)
```

---

## 8. No Contact Persistence

**Problem:** `contact.ContactManager` is in-memory only. On restart, all contacts
(and their shared secrets) are lost. The room server doesn't address this either —
it relies on adverts to repopulate contacts.

For a companion node that needs to reply to DMs, losing shared secrets means
incoming messages from known peers can't be decrypted until they re-advertise AND
the node recomputes shared secrets via ECDH.

**What we had to build:**
- A database table for MC nodes with pubkeys
- A `SeedContacts()` method that loads all known pubkeys from the database and
  pre-populates the contact manager on startup
- This ensures `GetSharedSecret()` works immediately for returning peers

**Suggested fix:** Support pluggable contact persistence in the contact manager,
or provide a serialization/deserialization interface.

---

## 9. MaxTextPayload Must Be Manually Calculated

**Problem:** The maximum text payload for a DM is not exposed by the library.
We had to derive it manually:

```
MaxPacketPayload (184)
- AddressedHeader (4 bytes: dest_hash + src_hash + MAC)
- AES-128 ECB padding (up to 15 bytes)
- TxtMsg header (5 bytes: timestamp 4 + type/attempt 1)
= ~160 bytes
```

**Suggested fix:** Export `MaxTxtMsgPayload` or provide a helper that computes
the available text bytes given the encryption overhead.

---

## Summary: What a `device/companion` Package Should Provide

1. **Packet handler** that processes ADVERT, TXT_MSG, PATH, and ACK packets
2. **Automatic ACK** for TxtTypePlain messages (with correct padding trim)
3. **SendDM helper** that handles encrypt → build → route for TxtTypePlain
4. **Contact path management** from flood packets (reverse + store)
5. **Configurable callbacks** for message receipt, advert discovery, ACK resolution
6. **Advert scheduling** (already exists in `device/advert`, works well)
7. **Exported constants** for payload limits
8. **Header construction helpers** to avoid manual bit shifting

The room server (`device/room`) is a good reference for all of these — most of
the logic exists but is private to that package and includes room-specific
concerns (client store, guest access, post storage, login flow).
