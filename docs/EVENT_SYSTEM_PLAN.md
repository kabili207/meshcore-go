# meshcore-go: Event System & Node Abstraction Plan

This document is the implementation plan for adding a typed event system and
node-type abstractions to meshcore-go. The goal is to bring the library to
parity with meshtastic-go in developer experience while supporting the three
main MeshCore node types (companion, room server, repeater) with a shared
foundation.

**Consumers:**
- [multi-mesh-bbs](https://github.com/kabili207/multi-mesh-bbs) — companion node (NodeTypeChat)
- [meshcore-room-server](https://github.com/kabili207/meshcore-room-server) — room server (NodeTypeRoom)
- Future: repeater nodes, bridge nodes (multi-identity)

**Reference implementation:** meshtastic-go's `device/event` and `device/node` packages.

---

## Design Principles

1. **The Node decrypts, not the consumer.** Events carry plaintext. Failed
   decryptions are dropped (or optionally surfaced via a debug event).
2. **Auto-ACK before emit.** Text message ACKs fire during packet processing,
   before the event reaches consumers. This matches firmware behavior.
3. **Auto-update contacts from adverts.** The Node updates the contact store
   on valid adverts, then emits an event so consumers can react.
4. **Append-style handlers.** `OnEvent(fn)` appends; multiple consumers
   receive all events. Replaces `SetPacketHandler`'s single-slot model.
5. **ReplyContext for responses.** Addressed events carry the shared secret
   and routing context so consumers can reply without re-deriving crypto.
6. **Room server becomes an event consumer.** The existing `device/room`
   dispatch is refactored onto the event system, eliminating duplicated
   decrypt/parse/ACK logic.

---

## Phase 1: Event Type Definitions

**Package:** `device/event`

Define the base types, handler signature, and all concrete event structs.
No dispatch logic yet — just the type definitions that all other phases build on.

### 1.1 Base Types

```go
package event

type Handler func(evt any)

type Event struct {
    From      core.MeshCoreID
    Timestamp time.Time
    RawPacket *codec.Packet
    Source    transport.PacketSource
}

type ReplyContext struct {
    SharedSecret  []byte
    FloodPath     []byte  // Reversed flood path from original packet (nil if direct)
    DirectPath    []byte  // Contact's stored direct path (nil if unknown)
    DirectPathLen int8    // -1 if unknown
}
```

### 1.2 Concrete Event Types

```go
// AdvertReceived — valid, non-replay ADVERT processed.
// Contact already updated in store before emit.
type AdvertReceived struct {
    Event
    Advert  *codec.AdvertPayload
    Contact *contact.ContactInfo
    IsNew   bool
}

// TextMessageReceived — decrypted text message, ACK already sent.
type TextMessageReceived struct {
    Event
    Reply   ReplyContext
    Message string
    TxtType uint8   // codec.TxtTypePlain, TxtTypeCLI, TxtTypeSigned
    Attempt uint8
}

// AckReceived — ACK packet, tracker already resolved.
type AckReceived struct {
    Event
    Checksum uint32
}

// AnonRequestReceived — decrypted anonymous request (login flow).
type AnonRequestReceived struct {
    Event
    Reply           ReplyContext
    EphemeralPubKey [32]byte
    Plaintext       []byte
}

// RequestReceived — decrypted addressed REQ.
type RequestReceived struct {
    Event
    Reply       ReplyContext
    RequestType uint8
    RequestData []byte
    Tag         uint32
}

// ResponseReceived — decrypted addressed RESPONSE.
type ResponseReceived struct {
    Event
    Reply     ReplyContext
    Plaintext []byte
}

// PathReceived — decrypted PATH, contact routing already updated.
// If the PATH bundles a known inner type (ACK, RESPONSE), that inner
// event is emitted instead and PathReceived is suppressed.
type PathReceived struct {
    Event
    Reply      ReplyContext
    ReturnPath []byte
    InnerType  uint8
    InnerData  []byte
}

// GroupTextReceived — unencrypted group text message.
type GroupTextReceived struct {
    Event
    ChannelHash []byte
    Message     string
}

// GroupDataReceived — unencrypted group datagram.
type GroupDataReceived struct {
    Event
    ChannelHash []byte
    Data        []byte
}

// PacketReceived — catch-all for unhandled payload types.
type PacketReceived struct {
    Event
}

// TransportStateChanged — transport connected/disconnected.
type TransportStateChanged struct {
    TransportName string
    State         transport.Event
}
```

### 1.3 Deliverables

- [x] `device/event/event.go` — Handler, Event, ReplyContext
- [x] `device/event/advert.go` — AdvertReceived
- [x] `device/event/message.go` — TextMessageReceived, GroupTextReceived, GroupDataReceived
- [x] `device/event/request.go` — RequestReceived, AnonRequestReceived, ResponseReceived
- [x] `device/event/ack.go` — AckReceived
- [x] `device/event/path.go` — PathReceived
- [x] `device/event/packet.go` — PacketReceived
- [x] `device/event/transport.go` — TransportStateChanged

---

## Phase 2: BaseNode & Event Dispatch

**Package:** `device/node`

The shared foundation for all node types. Owns identity, router, transports,
contacts, event dispatch, and the packet processing pipeline that converts
raw packets into typed events.

### 2.1 BaseNode Structure

```go
type BaseNode struct {
    // Identity
    identity  *crypto.KeyPair
    id        core.MeshCoreID

    // Core components
    router    *router.Router
    contacts  contact.ContactStore
    clock     *clock.Clock

    // Event system
    eventMu       sync.RWMutex
    eventHandlers []event.Handler

    // Configuration
    forwardPackets bool
    log            *slog.Logger
}
```

### 2.2 Packet → Event Pipeline

`BaseNode.processPacket` is registered as the router's `PacketHandler`.
It handles the protocol mechanics shared by all node types:

| Packet Type | BaseNode Processing | Event Emitted |
|---|---|---|
| ADVERT | Verify sig → reject replay → `ProcessAdvert()` → update contact → extract+reverse flood path | `AdvertReceived` |
| TXT_MSG | Find sender by hash → decrypt → parse content → **auto-ACK** → build ReplyContext | `TextMessageReceived` |
| ACK | Parse checksum → `ackTracker.Resolve()` | `AckReceived` |
| ANON_REQ | Decrypt with node privkey + ephemeral pubkey → build ReplyContext | `AnonRequestReceived` |
| REQ | Find sender → decrypt → parse request header → build ReplyContext | `RequestReceived` |
| RESPONSE | Find sender → decrypt → build ReplyContext | `ResponseReceived` |
| PATH | Find sender → decrypt → `ProcessPath()` → unwrap inner or emit PathReceived | Inner event or `PathReceived` |
| GRP_TXT | Parse group header | `GroupTextReceived` |
| GRP_DATA | Parse group header | `GroupDataReceived` |
| Other | — | `PacketReceived` |

### 2.3 PATH Unwrapping

When a PATH packet contains a known inner payload type:
- **ACK inner** → emit `AckReceived` (contact routing already updated)
- **RESPONSE inner** → emit `ResponseReceived` (with ReplyContext)
- **Unknown inner** → emit `PathReceived` with `InnerType` + `InnerData`

### 2.4 ReplyContext Construction

After successful decryption of an addressed packet, BaseNode builds:

```go
reply := event.ReplyContext{
    SharedSecret:  secret,           // From decryption attempt
    DirectPathLen: contact.OutPathLen,
    DirectPath:    contact.OutPath,
}
if pkt.IsFlood() && pkt.PathLen > 0 {
    reply.FloodPath = reverseFloodPath(pkt)
}
```

### 2.5 Shared Send Helpers

```go
// SendReply sends an encrypted response using a ReplyContext from a received event.
// Automatically chooses flood-with-PATH-return, direct, or plain flood routing
// based on available path information.
func (b *BaseNode) SendReply(ctx context.Context, reply event.ReplyContext,
    to core.MeshCoreID, payloadType uint8, plaintext []byte) error

// SendFloodReply sends a flood response, wrapping in PATH if the original
// was a flood packet (matches firmware room server behavior).
func (b *BaseNode) sendPathReturn(reply event.ReplyContext,
    to core.MeshCoreID, payloadType uint8, plaintext []byte) error
```

### 2.6 Exported Utilities

Move from room-server-private to exported:
- `codec.NewPacket(payloadType, routeType, payload)` — header construction helper
- `codec.ReverseFloodPath(pkt)` — path reversal utility
- `codec.MaxTxtMsgPayload` — exported constant for max text bytes after overhead

### 2.7 Deliverables

- [x] `device/node/base.go` — BaseNode struct, OnEvent, emitEvent, AddTransport, SendReply, sendPathReturn, sendACK, buildReplyContext
- [x] `device/node/dispatch.go` — processPacket pipeline, decryptAddressed, all payload type handlers
- [x] `core/codec/helpers.go` — NewPacket, ReverseFloodPath, TrimTxtMsgContent, TrimRequestContent
- [x] `device/node/dispatch_test.go` — Tests for advert, txtmsg, ack, anon_req, catch-all, multiple handlers

**Note:** decrypt, auto-ACK, and reply helpers were consolidated into base.go and
dispatch.go rather than separate files — the code is cleaner without the split.

---

## Phase 3: CompanionNode

**Package:** `device/node` (same package, separate file)

High-level node for companion/chat use cases (what the BBS needs).
Composes BaseNode with high-level send methods, ACK tracking, and optional
keep-alive.

### 3.1 CompanionNode Structure

```go
type CompanionNode struct {
    base        *BaseNode
    ackTracker  *ack.Tracker
    advertSched *AdvertScheduler  // generic callback-based (see Phase 5)
    connMgr     *connection.Manager  // optional
}

type CompanionConfig struct {
    // Identity
    PrivateKey ed25519.PrivateKey

    // Network
    Transports []TransportOption  // transport + source pairs

    // Contacts
    Contacts contact.ContactStore

    // Advertisement
    Name     string
    NodeType uint8  // codec.NodeTypeChat
    Lat      *float64
    Lon      *float64
    AdvertLocalInterval time.Duration
    AdvertFloodInterval time.Duration

    // Options
    ForwardPackets bool          // default: false
    ACKTimeout     time.Duration // default: 12s
    MaxRetries     int           // default: 3
    KeepAlive      *KeepAliveConfig // nil = disabled

    // Event handlers (can also use OnEvent after construction)
    EventHandlers []event.Handler

    Logger *slog.Logger
}
```

### 3.2 High-Level Send Methods

```go
// SendText encrypts and sends a text message. Handles chunking, encryption,
// header construction, and ACK tracking. Chooses direct vs flood routing
// based on contact path info.
func (n *CompanionNode) SendText(ctx context.Context, to core.MeshCoreID,
    message string, opts ...SendOption) error

// SendGroupText sends an unencrypted group text message.
func (n *CompanionNode) SendGroupText(ctx context.Context,
    channelHash []byte, message string) error

// SendReply delegates to BaseNode.SendReply for responding to events.
func (n *CompanionNode) SendReply(ctx context.Context, reply event.ReplyContext,
    to core.MeshCoreID, payloadType uint8, plaintext []byte) error
```

### 3.3 SendOption Pattern

```go
type SendOption func(*sendOptions)

func WithTxtType(t uint8) SendOption   // default: TxtTypePlain
func WithAttempt(a uint8) SendOption   // default: 0
func WithOnACK(fn func()) SendOption   // callback on ACK
func WithOnTimeout(fn func()) SendOption
func WithMaxChunks(n int) SendOption   // default: 1 (no chunking)
func WithChunkDelay(d time.Duration) SendOption // default: 500ms
```

### 3.4 Lifecycle

```go
func NewCompanion(cfg CompanionConfig) (*CompanionNode, error)

// Run starts all components and blocks until ctx is cancelled.
// Starts: transports, router, ACK tracker, advert scheduler, keep-alive.
func (n *CompanionNode) Run(ctx context.Context) error

// OnEvent registers an event handler (delegates to BaseNode).
func (n *CompanionNode) OnEvent(fn event.Handler)
```

### 3.5 Deliverables

- [x] `device/node/companion.go` — CompanionNode, CompanionConfig, NewCompanion, Run
- [x] `device/node/send.go` — SendText, splitMessage, SendOption (WithTxtType, WithAttempt, WithOnACK, WithOnTimeout, WithMaxChunks, WithChunkDelay)
- [x] `device/node/base.go` — Added StartTransports method and transports field
- [x] `device/node/companion_test.go` — Constructor, defaults, custom config tests
- [x] `device/node/send_test.go` — splitMessage tests (short, exact limit, newline split, no newline, empty)

---

## Phase 4: Refactor Room Server onto Events

**Package:** `device/room` (existing, modified)

The room server becomes an event consumer. It registers handlers via
`OnEvent` on a `RoomNode` (or directly on BaseNode). All decrypt/parse/ACK
logic is removed from the room package — the node handles it.

### 4.1 RoomNode Structure

```go
type RoomNode struct {
    base        *BaseNode
    server      *room.Server
    ackTracker  *ack.Tracker
    connMgr     *connection.Manager
    advertSched *AdvertScheduler
}

type RoomConfig struct {
    // Identity
    PrivateKey ed25519.PrivateKey

    // Network
    Transports []TransportOption
    ForwardPackets bool  // default: true (rooms typically relay)

    // Contacts
    Contacts contact.ContactStore

    // Room server config
    Room room.ServerConfig

    // Advertisement
    Name     string
    NodeType uint8  // codec.NodeTypeRoom
    Lat      *float64
    Lon      *float64
    AdvertLocalInterval time.Duration
    AdvertFloodInterval time.Duration

    // Options
    ACKTimeout time.Duration
    MaxRetries int
    KeepAlive  *KeepAliveConfig

    EventHandlers []event.Handler
    Logger        *slog.Logger
}
```

### 4.2 Room Server Changes

**Removed from `room.Server`:**
- `HandlePacket()` — no longer the entry point
- `handleAdvert()` — BaseNode does this
- `handleACK()` — BaseNode does this
- `handleAddressed()` — BaseNode decrypts, emits typed events
- All `crypto.*` and `codec.Parse*` calls in dispatch path
- `sendACK()` for text messages — BaseNode auto-ACKs

**Kept in `room.Server`:**
- Client session management (add/update/evict clients)
- Permission resolution (admin/guest/read-only)
- Post storage and retrieval
- Sync loop (timer-driven post push)
- CLI command execution
- Stats/telemetry providers
- Response building (login response, status, telemetry, ACL)

**Modified `room.Server`:**
- Constructor takes a `*BaseNode` (or reply-sending interface) instead of `*router.Router`
- `handleTextMessage()` receives `*event.TextMessageReceived` instead of raw packet
- `handleLogin()` receives `*event.AnonRequestReceived` instead of raw packet
- `handleRequest()` receives `*event.RequestReceived` instead of raw packet
- Response sending uses `node.SendReply()` instead of private `sendEncryptedResponse()`

### 4.3 Event Handler Wiring

```go
// Inside RoomNode.Run():
n.base.OnEvent(func(evt any) {
    switch e := evt.(type) {
    case *event.AnonRequestReceived:
        n.server.HandleLogin(e)
    case *event.TextMessageReceived:
        n.server.HandleTextMessage(e)
    case *event.RequestReceived:
        n.server.HandleRequest(e)
    case *event.PathReceived:
        n.server.HandlePath(e)
    case *event.AdvertReceived:
        n.server.HandleAdvert(e)  // update client routing info
    case *event.AckReceived:
        // ACK tracker already resolved by BaseNode — no-op unless
        // room server needs additional tracking
    }
})
```

### 4.4 Sync Loop Sending

The sync loop currently calls `sendEncryptedResponse()` to push posts.
After refactoring, it calls `node.SendReply()` (or a dedicated `node.SendText`
variant) with a pre-built ReplyContext from the stored contact info.

The sync loop constructs its own ReplyContext from the contact store:
```go
secret, _ := n.base.contacts.GetSharedSecret(clientID)
reply := event.ReplyContext{
    SharedSecret:  secret,
    DirectPath:    client.OutPath,
    DirectPathLen: client.OutPathLen,
}
n.base.SendReply(ctx, reply, clientID, codec.PayloadTypeTxtMsg, content)
```

### 4.5 Migration Strategy

This is a breaking change for the room server package API. Approach:

1. Add the event-based handler methods (`HandleLogin`, `HandleTextMessage`, etc.)
   alongside the existing `HandlePacket` method
2. Mark `HandlePacket` as deprecated
3. Update meshcore-room-server to use `RoomNode`
4. Remove `HandlePacket` and private dispatch methods in next minor version

### 4.6 Deliverables

- [x] `device/node/room.go` — RoomNode, RoomConfig, NewRoom, Run, dispatchToServer event wiring
- [x] `device/room/sender.go` — NodeSender interface (SendReply, SendACK, SendToContact)
- [x] `device/room/handlers.go` — event-based handlers: HandleLogin, HandleTextMessage, HandleRequest, HandlePath, HandleAdvertReceived
- [x] `device/room/server.go` — Added sender field, SetSender method
- [x] `device/room/sync.go` — pushPostToClient uses NodeSender when available, legacy fallback
- [x] `device/room/respond.go` — Removed duplicated reverseFloodPath (uses codec.ReverseFloodPath)
- [x] `device/room/dispatch.go` — Updated to use codec.TrimTxtMsgContent/TrimRequestContent
- [x] Removed `device/room/padding.go` — duplicates now in codec/helpers.go
- [x] `device/node/base.go` — Exported SendACK, added SendToContact (implements room.NodeSender)
- [ ] Update meshcore-room-server to use RoomNode
- [ ] Tests for room server event handlers (existing tests still pass via legacy path)

---

## Phase 5: Generic Broadcast Scheduler

**Package:** `device/node` (internal to node types)

Convert the protocol-specific `advert.Scheduler` to a generic callback-based
scheduler, matching meshtastic-go's `broadcast.Scheduler` pattern.

### 5.1 Current State

`advert.Scheduler` builds and sends advert packets itself. It knows about
advert payload construction, local vs flood intervals, and timer management.

### 5.2 Target State

A generic scheduler that accepts a `BroadcastFunc` callback. The caller
(node type) provides the function that builds the packet. This decouples
scheduling from packet construction.

```go
type BroadcastScheduler struct {
    localInterval time.Duration
    floodInterval time.Duration
    broadcastFunc func(flood bool) error
}

func (s *BroadcastScheduler) Start(ctx context.Context)
func (s *BroadcastScheduler) SendNow(flood bool)
```

### 5.3 Compatibility

The existing `advert.Scheduler` stays available for consumers that prefer
the self-contained approach. The generic scheduler is used internally by
node types.

`advert.NewSelfAdvertBuilder()` remains useful — it's the callback that
node types pass to the generic scheduler.

### 5.4 Deliverables

- [ ] `device/node/broadcast.go` — generic BroadcastScheduler
- [ ] Node types use generic scheduler + `advert.NewSelfAdvertBuilder()`
- [ ] Existing `advert.Scheduler` remains (not removed, not modified)

---

## Phase 6: RepeaterNode

**Package:** `device/node`

Minimal node type for packet relaying. Mostly BaseNode with forwarding
enabled and neighbor tracking.

### 6.1 RepeaterNode Structure

```go
type RepeaterNode struct {
    base        *BaseNode
    advertSched *BroadcastScheduler
}

type RepeaterConfig struct {
    PrivateKey  ed25519.PrivateKey
    Transports  []TransportOption
    Contacts    contact.ContactStore  // for neighbor tracking

    // Advertisement
    Name     string
    Lat      *float64
    Lon      *float64
    AdvertLocalInterval time.Duration
    AdvertFloodInterval time.Duration

    // Repeater-specific
    MaxFloodHops          int    // default: 64
    ValidateTransportCode router.TransportCodeValidator  // optional

    EventHandlers []event.Handler
    Logger        *slog.Logger
}
```

### 6.2 Behavior

- `ForwardPackets: true` (always)
- Processes ADVERTs for neighbor tracking
- Handles ANON_REQ for discovery responses (matches firmware)
- Minimal event emission: `AdvertReceived`, `TransportStateChanged`
- No text message handling, no ACK tracking, no keep-alive

### 6.3 Deliverables

- [x] `device/node/repeater.go` — RepeaterNode, RepeaterConfig, NewRepeater, Run
- [ ] Tests for forwarding behavior

---

## Phase 7: BridgeNode (Future)

**Package:** `device/node`

Multi-identity node managing multiple virtual MeshCoreIDs through a single
transport. See memory entry 576293247429984256 for full design notes.

This phase depends on Phase 2 (BaseNode) being stable. The firmware already
supports this — no protocol changes needed.

### 7.1 Key Concepts

- Manages N virtual identities, each with its own Ed25519 keypair
- Routes incoming packets to the correct identity by matching dest hash
- Sends on behalf of managed identities (sets source hash from their pubkey)
- Auto-responds to ADVERTs/REQs for managed nodes
- Functional callbacks for identity management:
  ```go
  IsManagedNode(hash byte) bool
  PrivateKeyForNode(id core.MeshCoreID) ed25519.PrivateKey
  PublicKeyForNode(id core.MeshCoreID) [32]byte
  ```

### 7.2 Deliverables

- [ ] `device/node/bridge.go` — BridgeNode, BridgeConfig
- [ ] Event.ManagedNodeID field (already in base Event, populated by BridgeNode)
- [ ] Design doc with identity dispatch flow

---

## Phase Dependency Graph

```
Phase 1 (Event types)
  └─→ Phase 2 (BaseNode + dispatch)
        ├─→ Phase 3 (CompanionNode)
        ├─→ Phase 4 (Room server refactor)
        ├─→ Phase 5 (Generic broadcast scheduler)
        │     └─→ used by Phases 3, 4, 6
        ├─→ Phase 6 (RepeaterNode)
        └─→ Phase 7 (BridgeNode) [future]
```

Phases 3, 4, 5, and 6 can be worked on in parallel once Phase 2 is complete.
Phase 5 is a dependency of 3/4/6 for the advert scheduler, but node types
can initially use the existing `advert.Scheduler` directly and migrate to the
generic one when it's ready.

---

## Consumer Migration Path

### multi-mesh-bbs (companion node)

**Before:**
```go
mqttTransport := mqtt.New(mqttCfg)
r := router.New(routerCfg)
r.AddTransport(mqttTransport, transport.PacketSourceMQTT)
contacts := contact.NewManager(privKey, contactCfg)
r.SetPacketHandler(handler.HandlePacket)  // 200+ lines of manual dispatch
```

**After:**
```go
node, _ := node.NewCompanion(node.CompanionConfig{
    PrivateKey: privKey,
    Transports: []node.TransportOption{{Transport: mqttTransport, Source: transport.PacketSourceMQTT}},
    Contacts:   contacts,
    Name:       "BBS",
    NodeType:   codec.NodeTypeChat,
    // ...
})
node.OnEvent(func(evt any) {
    switch e := evt.(type) {
    case *event.TextMessageReceived:
        commandProcessor.Handle(e.From, e.Message)
    case *event.AdvertReceived:
        // Contact already updated — maybe log or persist to DB
    }
})
node.Run(ctx)
```

### meshcore-room-server

**Before:**
```go
// ~100 lines of manual component wiring in main.go
mqttTransport := mqtt.New(mqttCfg)
r := router.New(routerCfg)
r.AddTransport(mqttTransport, transport.PacketSourceMQTT)
contacts := contact.NewManager(privKey, contactCfg)
ackTracker := ack.NewTracker(ackCfg)
connMgr := connection.NewManager(connCfg)
server := room.NewServer(serverCfg)
r.SetPacketHandler(server.HandlePacket)
// Start 7 background goroutines manually
```

**After:**
```go
node, _ := node.NewRoom(node.RoomConfig{
    PrivateKey: privKey,
    Transports: []node.TransportOption{{Transport: mqttTransport, Source: transport.PacketSourceMQTT}},
    Contacts:   contacts,
    Room:       roomCfg,
    Name:       "Room",
    NodeType:   codec.NodeTypeRoom,
    ForwardPackets: true,
    // ...
})
// Optional: add extra event handlers for observer/telemetry
node.OnEvent(observerHandler)
node.Run(ctx)
```

---

## Gaps Addressed

This plan addresses all items from `COMPANION_NODE_GAPS.md`:

| Gap | Phase | Resolution |
|---|---|---|
| 1. No auto ACK | 2 | BaseNode auto-ACKs in processPacket |
| 2. No companion handler | 2, 3 | BaseNode dispatch + CompanionNode |
| 3. No DM sending helper | 3 | CompanionNode.SendText() |
| 4. No flood path reversal | 2 | BaseNode reverses paths, exports utility |
| 5. No contact path management | 2 | BaseNode updates paths from floods + PATHs |
| 6. Direct routing issues | 2 | SendReply routing decision (investigate separately) |
| 7. Header bit shifting | 2 | codec.NewPacket() helper |
| 8. No contact persistence | — | Out of scope (store interface already exists) |
| 9. No MaxTextPayload | 2 | Exported constant |

---

## Implementation Notes

### Thread Safety

- `BaseNode.eventHandlers` protected by `RWMutex` (read lock during dispatch)
- Events dispatched synchronously — handlers must not block
- Contact store implementations must be thread-safe (already required)
- ACK tracker has internal synchronization (already implemented)

### Error Handling

- Decryption failures: silently dropped (debug-logged). No event emitted.
- Signature verification failures: silently dropped (debug-logged).
- Replay adverts (timestamp <= stored): silently dropped (debug-logged).
- Parse errors: debug-logged, `PacketReceived` emitted as fallback.

### Testing Strategy

- Mock transport that injects packets and captures sends
- Mock contact store with pre-seeded contacts and shared secrets
- Test each event type independently through the dispatch pipeline
- Integration tests: packet in → event out → reply sent
- Room server: verify equivalent behavior before/after refactor
