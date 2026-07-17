# device/console

Serves a node's text CLI over a byte stream (serial line, pty, or TCP socket) in
the exact shape [MeshMonitor](https://github.com/Yeraze/meshmonitor)'s
direct-repeater serial backend expects. This lets MeshMonitor connect to a
meshcore-go repeater or room server as if it were a physical MeshCore
infrastructure device, and monitor/configure it (stats, config, neighbors,
telemetry) over its normal serial-CLI path.

It does not implement the binary companion protocol, so companion-only features
(contacts, channels, direct messaging) are not exposed. Those live on a
different wire and would be a separate, much larger build.

## What it does

MeshMonitor's serial CLI contract, and how this adapter satisfies it:

- Commands arrive as UTF-8 text terminated by a single CR (`\r`). The adapter
  reads on that delimiter.
- MeshMonitor expects the command echoed back as the first reply line. The
  adapter echoes it.
- Replies are split on LF (`\n`) and accumulated until a line contains a
  completion token (`-> >`, `OK`, `Error`, or `Unknown command`); otherwise
  MeshMonitor waits out a multi-second timeout. The adapter terminates every
  reply with a `-> >` prompt line so completion is always immediate.
- `get name` is parsed with `/->\s*>\s*(.+)/` and `get radio` as four
  comma-separated numbers, so single-value replies are placed on the `-> >`
  line and multi-line replies (neighbors, ACL) are sent verbatim with the
  prompt as a trailing line.

meshcore-go's dispatcher returns bare values and never emits `-> >`; the adapter
supplies that framing. See the package doc comment for the details.

## Wiring a repeater

```go
rep, err := node.NewRepeater(node.RepeaterConfig{ /* ... */ })
if err != nil {
    return err
}

srv := console.NewServer(console.Config{
    Run:    rep.ExecuteCLI,
    Radio:  &console.RadioConfig{Freq: 910.525, BW: 250, SF: 11, CR: 5},
    Logger: logger,
})
```

`ExecuteCLI` on the repeater runs a command without the ACL/login gate that the
over-the-air path enforces, so the console is an unauthenticated local admin
surface. Treat the stream as trusted (a local serial device or a
loopback-bound socket).

## Wiring a room server

Identical, using `RoomNode.ExecuteCLI`:

```go
rm, err := node.NewRoom(node.RoomConfig{ /* ... */ })
if err != nil {
    return err
}

srv := console.NewServer(console.Config{
    Run:    rm.ExecuteCLI,
    Logger: logger,
})
```

Room note: the room server already registers `freq`, `bw`, `sf`, `cr`, and a
`radio` (model string) config key, so `get radio` natively returns the model
name, not the `freq,bw,sf,cr` tuple MeshMonitor's radio regex wants. If you need
that regex to match, set `Config.Radio` here too; the adapter intercepts
`get radio`/`set radio` before they reach the node. Leave `Radio` nil to let the
room answer natively.

## Serving it: pty vs TCP

The `Server` runs over any `io.ReadWriter`, so you choose the transport.

- **Serial / pty (no MeshMonitor changes):** MeshMonitor's direct-repeater mode
  is serial-only. Open a pty, point MeshMonitor's serial repeater source at the
  slave (`/dev/pts/N`), and hand the master to `Serve`:

  ```go
  // github.com/creack/pty (add it to YOUR module; this package stays dep-free)
  master, slave, _ := pty.Open()
  defer master.Close()
  fmt.Println("point MeshMonitor at", slave.Name()) // e.g. /dev/pts/7
  go srv.Serve(ctx, master)
  ```

  Open the port at 115200, 8-N-1, no flow control (MeshMonitor's defaults).

- **TCP (small MeshMonitor patch):** simpler to deploy and containerize, but
  MeshMonitor currently only reaches repeaters over serial, so it needs a change
  to allow a TCP repeater source.

  ```go
  go srv.ListenAndServe(ctx, "127.0.0.1:5000")
  ```

This package deliberately carries no pty dependency. The serial path pulls
`github.com/creack/pty` (or similar) into the consuming module; the TCP path is
standard-library only.

## Concurrency

A single `Serve` runs commands one at a time, so it never calls `Run`
concurrently with itself. `RoomNode.ExecuteCLI` is serialized under the room
server lock and is safe alongside over-the-air CLI. `RepeaterNode.ExecuteCLI` is
**not** synchronized against the repeater's over-the-air CLI goroutine; use the
console as that repeater's sole admin surface, or add your own locking.
