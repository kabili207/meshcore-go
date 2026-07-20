# device/companion

Serves the MeshCore **companion protocol** to a host app over a byte stream, so
a meshcore-go node presents itself as a companion device that an app connects to
and drives. It answers the connect handshake, streams contacts, exposes device
state, and relays messages both ways. Tested against the official MeshCore app
(`meshcore-flutter`) and compatible with MeshMonitor's MeshCore backend, which
speaks the same protocol over `@liamcottle/meshcore.js`.

The wire framing and payload codecs live in `core/codec/serial`. This package is
the stateful server: it accepts a connection, reads command frames, dispatches
them, and writes response/push frames.

## What it speaks

The companion protocol is a binary frame protocol. Each frame is
`[marker][u16 little-endian payload length][payload]`, where the marker is `0x3c`
for app→device (commands) and `0x3e` for device→app (responses and pushes), and
`payload[0]` is the command/response/push code. The framing is identical on
serial and TCP, so `ListenAndServe` (TCP) and `Serve` (any stream, e.g. a pty)
share one dispatch path. Over BLE the firmware drops the 3-byte header entirely;
this package does not implement BLE.

## Implemented

- **Handshake**: `APP_START` → `SELF_INFO`, `DEVICE_QUERY` → `DEVICE_INFO`. The
  server remembers the app's declared protocol version and uses it to pick the
  V3 vs pre-V3 layout for incoming-message frames.
- **Contacts**: `GET_CONTACTS` streaming with the `since` filter, plus
  `ADD_UPDATE_CONTACT`, `REMOVE_CONTACT`, `GET_CONTACT_BY_KEY`, `RESET_PATH`,
  `IMPORT_CONTACT` (verify and add a shared advert), and `EXPORT_CONTACT` of
  this node for a share URI/QR (via the `ExportSelf` callback). Exporting or
  `SHARE`-ing a *saved* contact returns `NOT_FOUND`: that rebroadcasts the
  contact's original signed advert, which meshcore-go's contact model does not
  store.
- **Device state**: device time, battery/storage, channels (`GET_CHANNEL` /
  `SET_CHANNEL`, with the built-in Public channel at index 0 and configurable
  128-bit channels at other indices), default flood scope, `GET_STATS`
  (core/radio/packets, wired to the router's packet counters), radio config
  (`SET_RADIO_PARAMS` / `SET_RADIO_TX_POWER` update the params reported in
  `SELF_INFO`, `GET`/`SET_TUNING_PARAMS`), auto-add config
  (`GET`/`SET_AUTOADD_CONFIG`), custom vars and advert-path reads, and the
  flood-scope / advert-name / config setters.
- **Direct messaging**: `SEND_TXT_MSG` → `SENT` with a `SEND_CONFIRMED` push on
  delivery, and incoming DMs delivered through the `MSG_WAITING` →
  `SYNC_NEXT_MESSAGE` queue as `CONTACT_MSG_RECV`.
- **Channel messaging**: `SEND_CHANNEL_TXT_MSG` (replies `OK`, not `SENT`, since
  group sends are unacknowledged broadcasts) and incoming group messages as
  `CHANNEL_MSG_RECV`.
- **Remote admin gateway**: `SEND_LOGIN` → `LOGIN_SUCCESS` (via the `SendLogin`
  callback and the node's `LoginResponse` event) logs the app into a repeater or
  room server. Admin CLI then rides the messaging path: the app sends commands
  as `SEND_TXT_MSG` with the CLI type, and replies return as `CONTACT_MSG_RECV`
  of the CLI type, which the app routes as `cli_reply`. `SEND_STATUS_REQ` →
  `STATUS_RESPONSE` (via `SendStatus` and the `StatusResponse` event) forwards a
  repeater's `RepeaterStats` blob for the app's health view, and
  `SEND_TELEMETRY_REQ` → `TELEMETRY_RESPONSE` forwards a remote node's
  CayenneLPP telemetry (a self request replies immediately, empty on a node
  without sensors), and `SEND_TRACE_PATH` → `TRACE_DATA` runs a traceroute along
  a relay-hash path (per-hop SNRs).
- **Live contact updates**: `NEW_ADVERT` (a first-seen node, sent as the full
  contact frame) and `ADVERT` (a re-heard node) are pushed automatically from the
  node's advert events, so the app's contact list updates without a manual
  refresh. `CONTACT_DELETED`, `PATH_UPDATED`, and `CONTACTS_FULL` are available
  as `Notify*` methods to wire to whatever signal you have (the example wires
  `CONTACT_DELETED` to the contact store's eviction callback).

Commands that are not implemented return `RESP_CODE_ERR / UNSUPPORTED_CMD`, which
the app reads as an old-firmware feature gate and degrades gracefully.

## Not yet wired

Path discovery (`SEND_PATH_DISCOVERY_REQ` → `PATH_DISCOVERY_RESPONSE`). The node
can send the request (`SendPathDiscovery`), but its result surfaces as a generic
`PathReceived` event that does not map cleanly to the `PATH_DISCOVERY_RESPONSE`
structure (pubkey prefix + out/in paths), so it is left unwired. Login failure is
also not surfaced: meshcore-go reports a bad-password login as a timeout rather
than a `LOGIN_FAIL` push.

## Wiring it

The server reads identity, contacts, and clock through a small `Node` interface
that `CompanionNode.Base()` satisfies. Sending and event delivery come in as
`Config` callbacks, which keeps this package decoupled from `device/node`.

```go
comp, err := node.NewCompanion(node.CompanionConfig{ /* key, transports, ... */ })
if err != nil {
    return err
}

srv := companion.NewServer(companion.Config{
    Node: comp.Base(),
    Identity: companion.Identity{
        Name:         "demo",
        RadioFreqMHz: 915.0,
        RadioBWkHz:   250,
        RadioSF:      11,
        RadioCR:      5,
    },

    // Deliver incoming messages: wire the server's handler to the node's events.
    Events: func(h func(evt any)) { comp.OnEvent(h) },

    // Outgoing direct message; return whether it went via flood, and invoke
    // onAck when the recipient acknowledges (drives SEND_CONFIRMED).
    SendDM: func(ctx context.Context, to core.MeshCoreID, text string, txtType, attempt uint8, onAck func()) (bool, error) {
        ct := comp.Base().Contacts().GetByPubKey(to)
        flood := ct == nil || !ct.HasDirectPath()
        err := comp.SendText(ctx, to, text,
            node.WithTxtType(txtType), node.WithAttempt(attempt), node.WithOnACK(onAck))
        return flood, err
    },

    // Outgoing channel message. The server resolves the channel index to its
    // key from its channel table and passes the key here.
    SendChannel: func(_ context.Context, channelKey []byte, text string) error {
        return comp.SendChannelText(channelKey, text)
    },
})

go srv.ListenAndServe(ctx, "127.0.0.1:5000")
```

`Identity` supplies everything the node doesn't model itself: radio params
(reported in `SELF_INFO`), firmware strings, GPS, battery, and storage. Sensible
defaults are filled in (firmware version code 13 / "v1.16.0", 4200 mV battery,
Public channel present). Leave `SendDM` / `SendChannel` / `Events` nil to run a
read-only server, in which case the corresponding commands return an error.

A runnable example lives in `examples/companion`.

## Serving it: TCP vs pty

- **TCP** (`ListenAndServe`): MeshMonitor's MeshCore backend connects to
  companion devices over TCP unmodified, so this is the primary entry point.
- **Serial / pty** (`Serve`): open a pty and hand the master to `Serve` to let a
  serial-only client (or the official app over USB) connect to `/dev/pts/N`.
  Open the port at 115200, 8-N-1, no flow control.

## The reply contract

The firmware replies to different commands with different frame types, and the
distinction is not guessable from the reverse-engineered clients (they get it
wrong). The rule, verified against the firmware source:

- `RESP_CODE_SENT` (followed by a `SEND_CONFIRMED` push) is used only for "send
  to a remote node and await an ACK" commands: `SEND_TXT_MSG`, `SEND_LOGIN`,
  `SEND_ANON_REQ`, `SEND_STATUS_REQ`, `SEND_PATH_DISCOVERY_REQ`,
  `SEND_TELEMETRY_REQ` (to a contact), `SEND_BINARY_REQ`, `SEND_TRACE_PATH`.
- A bare `RESP_CODE_OK` is used for broadcast/raw sends and every config write:
  `SEND_CHANNEL_TXT_MSG`, `SEND_CHANNEL_DATA`, `SEND_SELF_ADVERT`,
  `SEND_RAW_DATA`, `SEND_CONTROL_DATA`, `SEND_RAW_PACKET`, and the `SET_*`
  commands.

Getting this wrong is silent: the app accepts the connection but ignores the
action. A channel send answered with `SENT` instead of `OK`, for instance, left
messages unaccepted until the app reloaded the channel. The `EncodeSent` doc
comment in `core/codec/serial` restates this so future send handlers match it.

## Notes

- **One app at a time.** The incoming-message queue is shared across
  connections and drained by `SYNC_NEXT_MESSAGE`, which matches the firmware's
  single-queue model. Multiple simultaneous apps would race to drain it.
- **Approximations.** Incoming messages report `path_len` as `0xFF`
  (direct/unknown) and `snr` as 0, because the message events don't currently
  surface the raw packet's hop/signal data. Channel messages use the node clock
  as the sender timestamp, since the group event carries none. These are
  cosmetic (hop count and signal strength in the app), not correctness.
- **Error codes and push codes** in `core/codec/serial` match the firmware
  `ERR_CODE_*` / `PUSH_CODE_*` values, which the app decodes directly.
