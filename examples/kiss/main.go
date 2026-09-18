// Command kiss exercises both halves of the MeshCore KISS protocol.
//
// With -modem it acts as a KISS host: it opens a MeshCore KISS modem, prints
// what the modem reports about itself, and then logs every packet heard off the
// air with its signal report.
//
//	go run ./examples/kiss -modem /dev/ttyUSB0
//	go run ./examples/kiss -modem 192.168.1.50:8001    # KISS over TCP
//
// With -listen it acts as a KISS modem instead, bridging a UDP multicast mesh
// to any KISS client that connects. Packets a client sends are put on the mesh,
// and packets heard on the mesh are handed to every connected client.
//
//	go run ./examples/kiss -listen 127.0.0.1:8001
//
// The two modes can be combined to bridge a real radio to KISS clients over the
// network:
//
//	go run ./examples/kiss -modem /dev/ttyUSB0 -listen 0.0.0.0:8001
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	sloghelper "github.com/kabili207/slog-helper"

	"github.com/kabili207/meshcore-go/core/codec"
	kisscodec "github.com/kabili207/meshcore-go/core/codec/kiss"
	"github.com/kabili207/meshcore-go/core/crypto"
	kissmodem "github.com/kabili207/meshcore-go/device/kiss"
	"github.com/kabili207/meshcore-go/transport"
	kisshost "github.com/kabili207/meshcore-go/transport/kiss"
	"github.com/kabili207/meshcore-go/transport/udp"
)

func main() {
	sloghelper.InitFromEnv()

	if err := run(); err != nil {
		slog.Error("Fatal error", "error", err)
		os.Exit(1)
	}
}

type config struct {
	modem  string
	baud   int
	listen string
}

func run() error {
	var cfg config
	flag.StringVar(&cfg.modem, "modem", "", "KISS modem to drive: a serial port path or host:port for KISS over TCP")
	flag.IntVar(&cfg.baud, "baud", kisshost.DefaultBaudRate, "serial baud rate")
	flag.StringVar(&cfg.listen, "listen", "", "serve KISS clients on this address, bridging a UDP multicast mesh")
	flag.Parse()

	if cfg.modem == "" && cfg.listen == "" {
		flag.Usage()
		return errors.New("one of -modem or -listen is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var host *kisshost.Transport
	if cfg.modem != "" {
		var err error
		host, err = startHost(ctx, cfg)
		if err != nil {
			return err
		}
		defer host.Stop()
	}

	if cfg.listen != "" {
		if err := serveModem(ctx, cfg.listen, host); err != nil {
			return err
		}
		return nil
	}

	<-ctx.Done()
	return nil
}

// dialTCP reaches a modem exposed over the network by a KISS-over-TCP bridge.
func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// startHost opens the modem, reports what it says about itself, and logs
// received packets.
func startHost(ctx context.Context, cfg config) (*kisshost.Transport, error) {
	hostCfg := kisshost.Config{
		BaudRate: cfg.baud,
		OnRxMeta: func(packet *codec.Packet, meta kisshost.RxMeta) {
			slog.Debug("signal report", "snr_db", meta.SNR(), "rssi_dbm", meta.RSSI)
		},
	}
	// A serial port is a path; anything with a colon is an address.
	if strings.Contains(cfg.modem, ":") && !strings.HasPrefix(cfg.modem, "/") {
		conn, err := dialTCP(ctx, cfg.modem)
		if err != nil {
			slog.Error("Failed to reach the KISS modem", "address", cfg.modem, "error", err)
			return nil, err
		}
		hostCfg.Stream = conn
	} else {
		hostCfg.Port = cfg.modem
	}

	host := kisshost.New(hostCfg)
	host.SetPacketHandler(func(packet *codec.Packet, source transport.PacketSource) {
		slog.Info("packet received",
			"type", codec.PayloadTypeName(packet.PayloadType()),
			"route", codec.RouteTypeName(packet.RouteType()),
			"hops", packet.HopCount(),
			"snr_db", packet.GetSNR(),
			"bytes", len(packet.Payload),
		)
	})

	if err := host.Start(ctx); err != nil {
		slog.Error("Failed to open the KISS modem", "error", err)
		return nil, err
	}

	reportModem(ctx, host)
	return host, nil
}

// reportModem queries the modem and prints what it supports. Commands the
// hardware cannot answer come back as a NoCallback error, which is expected
// rather than fatal.
func reportModem(ctx context.Context, host *kisshost.Transport) {
	if err := host.Ping(ctx); err != nil {
		slog.Warn("Modem did not answer a ping", "error", err)
		return
	}

	if name, err := host.GetDeviceName(ctx); err == nil {
		fmt.Printf("device:     %s\n", name)
	}
	if v, err := host.GetVersion(ctx); err == nil {
		fmt.Printf("kiss proto: %d\n", v)
	}
	if pub, err := host.GetIdentity(ctx); err == nil {
		fmt.Printf("identity:   %s\n", hex.EncodeToString(pub))
	}
	if radio, err := host.GetRadio(ctx); err == nil {
		fmt.Printf("radio:      %.4f MHz, %.1f kHz BW, SF%d, CR4/%d\n",
			float64(radio.FreqHz)/1e6, float64(radio.BandwidthHz)/1e3,
			radio.SpreadingFactor, radio.CodingRate)
	}
	if power, err := host.GetTxPower(ctx); err == nil {
		fmt.Printf("tx power:   %d dBm\n", power)
	}
	if floor, err := host.GetNoiseFloor(ctx); err == nil {
		fmt.Printf("noise:      %d dBm\n", floor)
	}
	if stats, err := host.GetStats(ctx); err == nil {
		fmt.Printf("counters:   rx %d, tx %d, errors %d\n", stats.RxPackets, stats.TxPackets, stats.RxErrors)
	}
	if mv, err := host.GetBattery(ctx); err == nil {
		fmt.Printf("battery:    %d mV\n", mv)
	}
	if temp, err := host.GetMCUTemp(ctx); err == nil {
		fmt.Printf("mcu temp:   %.1f C\n", temp)
	}
}

// serveModem presents a KISS TNC to clients on addr. Its radio is either the
// real modem opened with -modem, or a UDP multicast mesh when there is none.
func serveModem(ctx context.Context, addr string, host *kisshost.Transport) error {
	key, err := crypto.GenerateKeyPair()
	if err != nil {
		slog.Error("Failed to generate an identity", "error", err)
		return err
	}

	var radio kissmodem.Radio
	var attach func(*kissmodem.Modem) error

	if host != nil {
		radio = kissmodem.RadioFunc(func(ctx context.Context, raw []byte) error {
			var packet codec.Packet
			if err := packet.ReadFrom(raw); err != nil {
				return err
			}
			return host.SendPacket(&packet)
		})
		attach = func(m *kissmodem.Modem) error {
			host.SetPacketHandler(func(packet *codec.Packet, _ transport.PacketSource) {
				m.Receive(packet.WriteTo(), kisscodec.RxMeta{SNRQuarterDB: packet.SNR})
			})
			return nil
		}
	} else {
		mesh := udp.New(udp.Config{})
		radio = kissmodem.RadioFunc(func(ctx context.Context, raw []byte) error {
			var packet codec.Packet
			if err := packet.ReadFrom(raw); err != nil {
				return err
			}
			return mesh.SendPacket(&packet)
		})
		attach = func(m *kissmodem.Modem) error {
			mesh.SetPacketHandler(func(packet *codec.Packet, _ transport.PacketSource) {
				m.Receive(packet.WriteTo(), kisscodec.RxMeta{SNRQuarterDB: packet.SNR})
			})
			if err := mesh.Start(ctx); err != nil {
				slog.Error("Failed to join the UDP mesh", "error", err)
				return err
			}
			return nil
		}
	}

	modem, err := kissmodem.New(kissmodem.Config{
		Radio:      radio,
		Identity:   key,
		DeviceName: "meshcore-go",
		// A bridged mesh has no carrier to sense and no keyup cost, so report a
		// clear channel and a nominal airtime.
		IsChannelBusy:   func() bool { return false },
		EstimateAirtime: func(n int) time.Duration { return time.Duration(n) * time.Millisecond },
		OnReboot:        func() { slog.Info("Client requested a reboot; ignoring") },
	})
	if err != nil {
		slog.Error("Failed to create the KISS modem", "error", err)
		return err
	}

	if err := attach(modem); err != nil {
		return err
	}

	slog.Info("Serving KISS clients", "addr", addr)
	if err := modem.ListenAndServe(ctx, addr); err != nil {
		slog.Error("KISS listener failed", "error", err)
		return err
	}
	return nil
}
