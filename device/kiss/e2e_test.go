package kiss_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	cayennelpp "github.com/TheThingsNetwork/go-cayenne-lib"
	"github.com/kabili207/meshcore-go/core/codec"
	kisscodec "github.com/kabili207/meshcore-go/core/codec/kiss"
	"github.com/kabili207/meshcore-go/core/crypto"
	kissmodem "github.com/kabili207/meshcore-go/device/kiss"
	"github.com/kabili207/meshcore-go/transport"
	kisshost "github.com/kabili207/meshcore-go/transport/kiss"
)

// fakeRadio records what the modem transmits and never fails.
type fakeRadio struct {
	mu   sync.Mutex
	sent [][]byte
	err  error
}

func (r *fakeRadio) Send(ctx context.Context, packet []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.sent = append(r.sent, append([]byte(nil), packet...))
	return nil
}

func (r *fakeRadio) packets() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.sent...)
}

// batteryProvider answers GetSensors with a single analog reading.
type batteryProvider struct{ volts float64 }

func (p batteryProvider) QuerySensors(permissions uint8, enc cayennelpp.Encoder) {
	if permissions&kisscodec.SensorPermBase != 0 {
		enc.AddAnalogInput(1, p.volts)
	}
}

// testRig is a host transport wired to a modem over an in-memory connection.
type testRig struct {
	host  *kisshost.Transport
	modem *kissmodem.Modem
	radio *fakeRadio
	key   *crypto.KeyPair
}

// newRig builds a modem with every optional hook supplied, unless cfg tweaks it,
// and connects a host transport to it. Everything is torn down via t.Cleanup.
func newRig(t *testing.T, tweak func(*kissmodem.Config)) *testRig {
	t.Helper()

	key, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	radio := &fakeRadio{}

	// Discard modem logs; a disconnecting host is noisy and expected.
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := kissmodem.Config{
		Radio:           radio,
		Identity:        key,
		DeviceName:      "test modem",
		Logger:          quiet,
		SetRadio:        func(kisscodec.RadioConfig) error { return nil },
		SetTxPower:      func(uint8) error { return nil },
		IsChannelBusy:   func() bool { return false },
		CurrentRSSI:     func() int8 { return -97 },
		NoiseFloor:      func() int16 { return -122 },
		EstimateAirtime: func(n int) time.Duration { return time.Duration(n) * time.Millisecond },
		Stats:           func() kisscodec.Stats { return kisscodec.Stats{RxPackets: 7, TxPackets: 3, RxErrors: 1} },
		Battery:         func() uint16 { return 4012 },
		MCUTemp:         func() (float32, bool) { return 25.3, true },
		Telemetry:       batteryProvider{volts: 4.012},
		OnReboot:        func() {},
	}
	if tweak != nil {
		tweak(&cfg)
	}

	modem, err := kissmodem.New(cfg)
	if err != nil {
		t.Fatalf("New modem: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())

	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = modem.Serve(ctx, serverConn)
	}()

	host := kisshost.New(kisshost.Config{
		Stream:         clientConn,
		TxTimeout:      5 * time.Second,
		RequestTimeout: 5 * time.Second,
		Logger:         quiet,
	})
	if err := host.Start(ctx); err != nil {
		t.Fatalf("host Start: %v", err)
	}

	// Transmit immediately rather than sitting through the default half-second
	// keyup delay and CSMA backoff.
	if err := host.SetTxDelay(0); err != nil {
		t.Fatalf("SetTxDelay: %v", err)
	}
	if err := host.SetPersistence(255); err != nil {
		t.Fatalf("SetPersistence: %v", err)
	}

	t.Cleanup(func() {
		_ = host.Stop()
		cancel()
		serverConn.Close()
		<-served
	})

	return &testRig{host: host, modem: modem, radio: radio, key: key}
}

func TestHardwareRoundTrips(t *testing.T) {
	rig := newRig(t, nil)
	ctx := context.Background()

	t.Run("ping", func(t *testing.T) {
		if err := rig.host.Ping(ctx); err != nil {
			t.Errorf("Ping: %v", err)
		}
	})

	t.Run("version", func(t *testing.T) {
		v, err := rig.host.GetVersion(ctx)
		if err != nil {
			t.Fatalf("GetVersion: %v", err)
		}
		if v != kisscodec.FirmwareVersion {
			t.Errorf("GetVersion = %d, want %d", v, kisscodec.FirmwareVersion)
		}
	})

	t.Run("device name", func(t *testing.T) {
		name, err := rig.host.GetDeviceName(ctx)
		if err != nil {
			t.Fatalf("GetDeviceName: %v", err)
		}
		if name != "test modem" {
			t.Errorf("GetDeviceName = %q", name)
		}
	})

	t.Run("identity", func(t *testing.T) {
		pub, err := rig.host.GetIdentity(ctx)
		if err != nil {
			t.Fatalf("GetIdentity: %v", err)
		}
		if !bytes.Equal(pub, rig.key.PublicKey) {
			t.Errorf("GetIdentity = %x, want %x", pub, rig.key.PublicKey)
		}
	})

	t.Run("random", func(t *testing.T) {
		b, err := rig.host.GetRandom(ctx, 32)
		if err != nil {
			t.Fatalf("GetRandom: %v", err)
		}
		if len(b) != 32 {
			t.Errorf("GetRandom returned %d bytes, want 32", len(b))
		}
		if bytes.Equal(b, make([]byte, 32)) {
			t.Error("GetRandom returned all zeros")
		}
	})

	t.Run("random out of range", func(t *testing.T) {
		if _, err := rig.host.GetRandom(ctx, 0); err == nil {
			t.Error("expected a client-side error for length 0")
		}
	})

	t.Run("sign and verify", func(t *testing.T) {
		msg := []byte("the quick brown fox")

		sig, err := rig.host.SignData(ctx, msg)
		if err != nil {
			t.Fatalf("SignData: %v", err)
		}
		if !ed25519.Verify(rig.key.PublicKey, msg, sig) {
			t.Fatal("modem signature does not verify locally")
		}

		ok, err := rig.host.VerifySignature(ctx, rig.key.PublicKey, sig, msg)
		if err != nil {
			t.Fatalf("VerifySignature: %v", err)
		}
		if !ok {
			t.Error("VerifySignature rejected a good signature")
		}

		ok, err = rig.host.VerifySignature(ctx, rig.key.PublicKey, sig, []byte("tampered"))
		if err != nil {
			t.Fatalf("VerifySignature: %v", err)
		}
		if ok {
			t.Error("VerifySignature accepted a signature over different data")
		}
	})

	t.Run("hash", func(t *testing.T) {
		data := []byte("hash me")
		got, err := rig.host.Hash(ctx, data)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		want := sha256.Sum256(data)
		if !bytes.Equal(got, want[:]) {
			t.Errorf("Hash = %x, want %x", got, want)
		}
	})

	t.Run("key exchange", func(t *testing.T) {
		peer, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}

		got, err := rig.host.KeyExchange(ctx, peer.PublicKey)
		if err != nil {
			t.Fatalf("KeyExchange: %v", err)
		}
		// The peer computing from its own side must land on the same secret.
		want, err := crypto.ComputeSharedSecret(peer.PrivateKey, rig.key.PublicKey)
		if err != nil {
			t.Fatalf("ComputeSharedSecret: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("KeyExchange = %x, want %x", got, want)
		}
	})

	t.Run("encrypt and decrypt", func(t *testing.T) {
		secret := bytes.Repeat([]byte{0x5A}, kisscodec.PubKeySize)
		plaintext := []byte("meshcore")

		sealed, err := rig.host.EncryptData(ctx, secret, plaintext)
		if err != nil {
			t.Fatalf("EncryptData: %v", err)
		}
		if len(sealed) != kisscodec.CipherMACSize+16 {
			t.Errorf("sealed length = %d, want %d", len(sealed), kisscodec.CipherMACSize+16)
		}

		got, err := rig.host.DecryptData(ctx, secret, sealed)
		if err != nil {
			t.Fatalf("DecryptData: %v", err)
		}
		// The cipher zero-pads, so only the prefix is meaningful.
		if !bytes.HasPrefix(got, plaintext) {
			t.Errorf("DecryptData = %x, want prefix %x", got, plaintext)
		}
	})

	t.Run("decrypt with wrong secret fails", func(t *testing.T) {
		secret := bytes.Repeat([]byte{0x5A}, kisscodec.PubKeySize)
		sealed, err := rig.host.EncryptData(ctx, secret, []byte("meshcore"))
		if err != nil {
			t.Fatalf("EncryptData: %v", err)
		}

		wrong := bytes.Repeat([]byte{0x11}, kisscodec.PubKeySize)
		_, err = rig.host.DecryptData(ctx, wrong, sealed)
		var hwErr *kisscodec.HardwareError
		if !errors.As(err, &hwErr) || hwErr.Code != kisscodec.HWErrMacFailed {
			t.Errorf("DecryptData error = %v, want MAC failure", err)
		}
	})

	t.Run("radio config", func(t *testing.T) {
		want := kisscodec.RadioConfig{FreqHz: 869618000, BandwidthHz: 62500, SpreadingFactor: 11, CodingRate: 5}
		if err := rig.host.SetRadio(ctx, want); err != nil {
			t.Fatalf("SetRadio: %v", err)
		}
		got, err := rig.host.GetRadio(ctx)
		if err != nil {
			t.Fatalf("GetRadio: %v", err)
		}
		if got != want {
			t.Errorf("GetRadio = %+v, want %+v", got, want)
		}
	})

	t.Run("tx power", func(t *testing.T) {
		if err := rig.host.SetTxPower(ctx, 22); err != nil {
			t.Fatalf("SetTxPower: %v", err)
		}
		got, err := rig.host.GetTxPower(ctx)
		if err != nil {
			t.Fatalf("GetTxPower: %v", err)
		}
		if got != 22 {
			t.Errorf("GetTxPower = %d, want 22", got)
		}
	})

	t.Run("signal readings", func(t *testing.T) {
		rssi, err := rig.host.GetCurrentRSSI(ctx)
		if err != nil {
			t.Fatalf("GetCurrentRSSI: %v", err)
		}
		if rssi != -97 {
			t.Errorf("GetCurrentRSSI = %d, want -97", rssi)
		}

		floor, err := rig.host.GetNoiseFloor(ctx)
		if err != nil {
			t.Fatalf("GetNoiseFloor: %v", err)
		}
		if floor != -122 {
			t.Errorf("GetNoiseFloor = %d, want -122", floor)
		}

		busy, err := rig.host.IsChannelBusy(ctx)
		if err != nil {
			t.Fatalf("IsChannelBusy: %v", err)
		}
		if busy {
			t.Error("IsChannelBusy = true, want false")
		}

		airtime, err := rig.host.GetAirtime(ctx, 200)
		if err != nil {
			t.Fatalf("GetAirtime: %v", err)
		}
		if airtime != 200*time.Millisecond {
			t.Errorf("GetAirtime = %v, want 200ms", airtime)
		}
	})

	t.Run("status", func(t *testing.T) {
		stats, err := rig.host.GetStats(ctx)
		if err != nil {
			t.Fatalf("GetStats: %v", err)
		}
		want := kisscodec.Stats{RxPackets: 7, TxPackets: 3, RxErrors: 1}
		if stats != want {
			t.Errorf("GetStats = %+v, want %+v", stats, want)
		}

		mv, err := rig.host.GetBattery(ctx)
		if err != nil {
			t.Fatalf("GetBattery: %v", err)
		}
		if mv != 4012 {
			t.Errorf("GetBattery = %d, want 4012", mv)
		}

		temp, err := rig.host.GetMCUTemp(ctx)
		if err != nil {
			t.Fatalf("GetMCUTemp: %v", err)
		}
		if temp != 25.3 {
			t.Errorf("GetMCUTemp = %v, want 25.3", temp)
		}
	})

	t.Run("sensors", func(t *testing.T) {
		payload, err := rig.host.GetSensors(ctx, kisscodec.SensorPermAll)
		if err != nil {
			t.Fatalf("GetSensors: %v", err)
		}
		if len(payload) == 0 {
			t.Fatal("GetSensors returned no CayenneLPP payload")
		}

		// A permission mask that excludes the battery must yield nothing.
		payload, err = rig.host.GetSensors(ctx, kisscodec.SensorPermLocation)
		if err != nil {
			t.Fatalf("GetSensors: %v", err)
		}
		if len(payload) != 0 {
			t.Errorf("GetSensors without base permission returned %x", payload)
		}
	})

	t.Run("signal report toggle", func(t *testing.T) {
		enabled, err := rig.host.GetSignalReport(ctx)
		if err != nil {
			t.Fatalf("GetSignalReport: %v", err)
		}
		if !enabled {
			t.Error("signal reporting should default to enabled")
		}

		enabled, err = rig.host.SetSignalReport(ctx, false)
		if err != nil {
			t.Fatalf("SetSignalReport: %v", err)
		}
		if enabled {
			t.Error("SetSignalReport(false) reported still enabled")
		}

		if _, err := rig.host.SetSignalReport(ctx, true); err != nil {
			t.Fatalf("SetSignalReport: %v", err)
		}
	})
}

func TestUnavailableFeaturesReportNoCallback(t *testing.T) {
	rig := newRig(t, func(cfg *kissmodem.Config) {
		cfg.Identity = nil
		cfg.MCUTemp = nil
		cfg.Stats = nil
		cfg.SetRadio = nil
	})
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{"identity", func() error { _, err := rig.host.GetIdentity(ctx); return err }},
		{"sign", func() error { _, err := rig.host.SignData(ctx, []byte("x")); return err }},
		{"key exchange", func() error {
			_, err := rig.host.KeyExchange(ctx, make([]byte, kisscodec.PubKeySize))
			return err
		}},
		{"mcu temp", func() error { _, err := rig.host.GetMCUTemp(ctx); return err }},
		{"stats", func() error { _, err := rig.host.GetStats(ctx); return err }},
		{"set radio", func() error { return rig.host.SetRadio(ctx, kisscodec.RadioConfig{}) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hwErr *kisscodec.HardwareError
			err := tt.call()
			if !errors.As(err, &hwErr) || hwErr.Code != kisscodec.HWErrNoCallback {
				t.Errorf("error = %v, want HWErrNoCallback", err)
			}
		})
	}

	t.Run("hash still works without an identity", func(t *testing.T) {
		if _, err := rig.host.Hash(ctx, []byte("x")); err != nil {
			t.Errorf("Hash: %v", err)
		}
	})
}

func TestSendPacketReachesRadio(t *testing.T) {
	rig := newRig(t, nil)

	packet := &codec.Packet{
		Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: []byte{0x01, 0x02, 0x03, 0x04},
	}

	if err := rig.host.SendPacket(packet); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}

	sent := rig.radio.packets()
	if len(sent) != 1 {
		t.Fatalf("radio saw %d packets, want 1", len(sent))
	}
	if !bytes.Equal(sent[0], packet.WriteTo()) {
		t.Errorf("radio got %x, want %x", sent[0], packet.WriteTo())
	}
}

func TestSendPacketReportsRadioFailure(t *testing.T) {
	rig := newRig(t, nil)
	rig.radio.mu.Lock()
	rig.radio.err = errors.New("antenna disconnected")
	rig.radio.mu.Unlock()

	err := rig.host.SendPacket(&codec.Packet{
		Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: []byte{0x09},
	})
	if !errors.Is(err, kisshost.ErrTxFailed) {
		t.Errorf("SendPacket error = %v, want ErrTxFailed", err)
	}
}

func TestStopReleasesASendWaitingOnTheRadio(t *testing.T) {
	// A transmission can sit in CSMA backoff for a long time, and TxTimeout is
	// generous to allow for it. Losing the modem must not leave the sender
	// blocked for the rest of that window holding the transmit lock.
	entered := make(chan struct{}, 1)
	rig := newRig(t, func(cfg *kissmodem.Config) {
		cfg.Radio = kissmodem.RadioFunc(func(ctx context.Context, _ []byte) error {
			entered <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		})
	})

	sent := make(chan error, 1)
	go func() {
		sent <- rig.host.SendPacket(&codec.Packet{
			Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeFlood,
			Payload: []byte{0x77},
		})
	}()

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the packet never reached the radio")
	}

	if err := rig.host.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// The rig's TxTimeout is 5s, so returning inside 2s proves Stop released
	// the sender rather than the timeout expiring.
	select {
	case err := <-sent:
		if !errors.Is(err, kisshost.ErrNotConnected) {
			t.Errorf("SendPacket error = %v, want ErrNotConnected", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendPacket was still blocked two seconds after Stop")
	}
}

func TestReceiveDeliversPacketWithSignalReport(t *testing.T) {
	rig := newRig(t, nil)

	received := make(chan *codec.Packet, 1)
	rig.host.SetPacketHandler(func(p *codec.Packet, source transport.PacketSource) {
		if source != transport.PacketSourceKISS {
			t.Errorf("packet source = %v, want kiss", source)
		}
		select {
		case received <- p:
		default:
		}
	})

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: []byte{0xAA, 0xBB},
	}
	meta := kisscodec.RxMeta{SNRQuarterDB: -30, RSSI: -101}
	rig.modem.Receive(pkt.WriteTo(), meta)

	select {
	case got := <-received:
		if got.SNR != meta.SNRQuarterDB {
			t.Errorf("packet SNR = %d, want %d", got.SNR, meta.SNRQuarterDB)
		}
		if got.GetSNR() != -7.5 {
			t.Errorf("GetSNR = %v, want -7.5", got.GetSNR())
		}
		if !bytes.Equal(got.Payload, []byte{0xAA, 0xBB}) {
			t.Errorf("payload = %x", got.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the received packet")
	}
}

func TestReceiveWithoutSignalReportStillDelivers(t *testing.T) {
	rig := newRig(t, nil)
	ctx := context.Background()

	if _, err := rig.host.SetSignalReport(ctx, false); err != nil {
		t.Fatalf("SetSignalReport: %v", err)
	}

	received := make(chan *codec.Packet, 1)
	rig.host.SetPacketHandler(func(p *codec.Packet, _ transport.PacketSource) {
		select {
		case received <- p:
		default:
		}
	})

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: []byte{0xCC},
	}
	rig.modem.Receive(pkt.WriteTo(), kisscodec.RxMeta{SNRQuarterDB: 20, RSSI: -80})

	select {
	case got := <-received:
		// No RxMeta arrives, so the packet is released by the hold timer with
		// SNR left unset.
		if got.SNR != 0 {
			t.Errorf("packet SNR = %d, want 0 with reporting disabled", got.SNR)
		}
		if !bytes.Equal(got.Payload, []byte{0xCC}) {
			t.Errorf("payload = %x", got.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the received packet")
	}
}
