# meshcore-go

A Go implementation of the MeshCore protocol for mesh networking over LoRa radios.

## Overview

This library provides Go packages for building MeshCore mesh networking applications:

- **Core protocol** - Packet encoding/decoding, routing, crypto
- **Device implementations** - Room server, repeater, companion node
- **Transports** - Serial (RS232), MQTT

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

### transport

Network transports:

- **serial** - RS232 serial connection
- **mqtt** - MQTT bridge for extending networks

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

The MQTT transport aligns with the [MQTTBridge firmware fork](https://github.com/vrybdpkt/MeshCore) which adds MQTT bridging support to MeshCore repeaters.

## Protocol

MeshCore is a lightweight mesh routing protocol for LoRa radios. See [meshcore.io](https://meshcore.io) for the full protocol specification.

## Resources

- Firmware: [meshcore-dev/MeshCore](https://github.com/meshcore-dev/MeshCore)