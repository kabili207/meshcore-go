# meshcore-go

A Go implementation of the MeshCore protocol for mesh networking over LoRa radios.

## Overview

This library provides Go packages for building MeshCore mesh networking applications:

- **Core protocol** - Packet encoding/decoding, routing, crypto
- **Device implementations** - Room server, repeater, companion node, KISS modem
- **Transports** - Serial (RS232), MQTT, UDP multicast, KISS TNC

## Packages

### core/codec

Packet encoding/decoding with support for:

- All payload types (advert, text, direct, ack, trace, etc.)
- RS232 framing with Fletcher-16 checksums
- Path hashing

### core/crypto

Encryption and authentication:

- AES-CCM for packet encryption
- Ed25519 for signing
- Group encryption

### device

Device role implementations:

- **room** - Room server (mesh routing hub)
- **node** - Repeater and companion node logic
- **contact** - Contact list management
- **router** - Packet routing with loop detection
- **kiss** - KISS TNC server presenting a radio to KISS clients

### transport

Network transports:

- **serial** - RS232 serial connection
- **mqtt** - MQTT bridge for extending networks
- **udp** - UDP multicast for local mesh links
- **kiss** - KISS modem, the one path to a real LoRa radio

## Usage

```go
import (
    "github.com/kabili207/meshcore-go/core/codec"
    "github.com/kabili207/meshcore-go/transport/serial"
)

cfg := serial.Config{
    Port: "/dev/ttyUSB0",
    BaudRate: 115200,
}
tr := serial.New(cfg)
```

The MQTT transport speaks to firmware forks that add MQTT bridging to MeshCore repeaters. The forks use different payload formats, so pick the one your repeaters run:

| `Framing` | Firmware | Payload | Default topic |
|-----------|----------|---------|---------------|
| `mqtt.FramingBridge` (default) | [xJARiD/MeshCore-EastMesh](https://github.com/xJARiD/MeshCore-EastMesh) | magic + Fletcher-16 + packet, XORed with `Secret` | `meshcore/bridge/packets` |
| `mqtt.FramingRaw` | [vrybdpkt/MeshCore](https://github.com/vrybdpkt/MeshCore) | bare packet bytes | `meshcore/bridge` |

For EastMesh, `Secret` is the repeater's `bridge.secret`. That firmware's bridge connects over plain TCP only, so the broker needs a non-TLS listener for the repeaters even if this side uses `UseTLS`.

To put a node on real RF, point the KISS transport at a MeshCore KISS modem:

```go
tr := kiss.New(kiss.Config{Port: "/dev/ttyUSB0"})
```

It carries raw packets both ways and exposes the modem's SetHardware extensions
(radio settings, RSSI and noise floor, telemetry, crypto) as methods. `device/kiss`
is the other half, serving KISS clients over a stream or TCP. See
`examples/kiss` for both.

## Protocol

MeshCore is a lightweight mesh routing protocol for LoRa radios. See [meshcore.io](https://meshcore.io) for the full protocol specification.

## Resources

- Firmware: [meshcore-dev/MeshCore](https://github.com/meshcore-dev/MeshCore)