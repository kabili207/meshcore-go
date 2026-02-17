// Package mqtt provides an MQTT transport for connecting to MeshCore mesh networks.
//
// MeshCore packets are transmitted as base64-encoded strings over MQTT topics
// in the format "{prefix}/{meshID}". This transport connects to any standard
// MQTT broker and subscribes to receive packets for a given mesh ID.
package mqtt

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

// Compile-time interface check.
var _ transport.Transport = (*Transport)(nil)

const (
	// DefaultTopicPrefix is the default MQTT topic prefix for MeshCore packets.
	DefaultTopicPrefix = "meshcore"
)

// Config holds the configuration for an MQTT transport.
type Config struct {
	// Broker is the MQTT broker URL (e.g., "tcp://broker.example.com:1883").
	Broker string
	// Username for MQTT authentication. Leave empty if not required.
	Username string
	// Password for MQTT authentication. Leave empty if not required.
	Password string
	// UseTLS enables TLS for the MQTT connection.
	UseTLS bool
	// ClientID is the MQTT client identifier. If empty, a random one is generated.
	ClientID string
	// TopicPrefix is the MQTT topic prefix (default: "meshcore").
	TopicPrefix string
	// MeshID identifies this mesh network (e.g., "my-mesh"). The transport
	// subscribes to "{TopicPrefix}/{MeshID}" and publishes to the same topic.
	MeshID string
	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// Transport implements transport.Transport over MQTT.
type Transport struct {
	cfg           Config
	client        paho.Client
	log           *slog.Logger
	mu            sync.RWMutex
	connected     bool
	packetHandler transport.PacketHandler
	stateHandler  transport.StateHandler
}

// New creates a new MQTT transport with the given configuration.
func New(cfg Config) *Transport {
	if cfg.TopicPrefix == "" {
		cfg.TopicPrefix = DefaultTopicPrefix
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Transport{
		cfg: cfg,
		log: cfg.Logger.WithGroup("mqtt"),
	}
}

// Start connects to the MQTT broker and begins listening for packets.
func (t *Transport) Start(ctx context.Context) error {
	if t.cfg.Broker == "" {
		return errors.New("broker URL is required")
	}
	if t.cfg.MeshID == "" {
		return errors.New("mesh ID is required")
	}

	clientID := t.cfg.ClientID
	if clientID == "" {
		clientID = "meshcore-" + randomString(16)
	}

	opts := paho.NewClientOptions().
		AddBroker(t.cfg.Broker).
		SetClientID(clientID).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(5 * time.Second).
		SetMaxReconnectInterval(2 * time.Minute).
		SetKeepAlive(60 * time.Second).
		SetPingTimeout(10 * time.Second).
		SetCleanSession(true).
		SetOrderMatters(false).
		SetOnConnectHandler(t.onConnected).
		SetConnectionLostHandler(t.onConnectionLost).
		SetReconnectingHandler(t.onReconnecting)

	if t.cfg.Username != "" {
		opts.SetUsername(t.cfg.Username)
	}
	if t.cfg.Password != "" {
		opts.SetPassword(t.cfg.Password)
	}
	if t.cfg.UseTLS {
		opts.SetTLSConfig(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})
	}

	t.client = paho.NewClient(opts)

	token := t.client.Connect()
	if !token.WaitTimeout(30 * time.Second) {
		return errors.New("connection timeout")
	}
	if token.Error() != nil {
		return fmt.Errorf("connecting to broker: %w", token.Error())
	}

	return nil
}

// Stop gracefully disconnects from the MQTT broker.
func (t *Transport) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client != nil {
		t.client.Disconnect(1000)
		t.connected = false
	}
	return nil
}

// IsConnected returns true if the transport is connected to the broker.
func (t *Transport) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connected && t.client != nil && t.client.IsConnected()
}

// SetPacketHandler sets the callback for incoming MeshCore packets.
func (t *Transport) SetPacketHandler(fn transport.PacketHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.packetHandler = fn
}

// SetStateHandler sets the callback for transport state changes.
func (t *Transport) SetStateHandler(fn transport.StateHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stateHandler = fn
}

// SendPacket encodes a MeshCore packet and publishes it to the mesh topic.
func (t *Transport) SendPacket(packet *codec.Packet) error {
	if !t.IsConnected() {
		return errors.New("not connected")
	}

	data := packet.WriteTo()
	payload := base64.StdEncoding.EncodeToString(data)
	topic := t.cfg.TopicPrefix + "/" + t.cfg.MeshID

	token := t.client.Publish(topic, 0, false, payload)
	if !token.WaitTimeout(10 * time.Second) {
		return errors.New("timeout publishing to MQTT")
	}
	return token.Error()
}

func (t *Transport) topic() string {
	return t.cfg.TopicPrefix + "/" + t.cfg.MeshID
}

func (t *Transport) subscribe() {
	topic := t.topic()
	t.client.Subscribe(topic, 0, t.handleMessage)
	t.log.Debug("subscribed to mesh topic", "topic", topic)
}

func (t *Transport) handleMessage(_ paho.Client, message paho.Message) {
	t.mu.RLock()
	handler := t.packetHandler
	t.mu.RUnlock()

	if handler == nil {
		return
	}

	rawData, err := base64.StdEncoding.DecodeString(string(message.Payload()))
	if err != nil {
		t.log.Debug("failed to decode base64 payload", "error", err)
		return
	}

	var packet codec.Packet
	if err := packet.ReadFrom(rawData); err != nil {
		t.log.Debug("failed to parse MeshCore packet", "error", err)
		return
	}

	handler(&packet, transport.PacketSourceMQTT)
}

func (t *Transport) onConnected(_ paho.Client) {
	t.mu.Lock()
	t.connected = true
	handler := t.stateHandler
	t.mu.Unlock()

	t.subscribe()
	t.log.Info("connected to MQTT broker", "broker", t.cfg.Broker)

	if handler != nil {
		handler(t, transport.EventConnected)
	}
}

func (t *Transport) onConnectionLost(_ paho.Client, err error) {
	t.mu.Lock()
	t.connected = false
	handler := t.stateHandler
	t.mu.Unlock()

	t.log.Error("MQTT connection lost", "error", err)

	if handler != nil {
		handler(t, transport.EventDisconnected)
	}
}

func (t *Transport) onReconnecting(_ paho.Client, _ *paho.ClientOptions) {
	t.mu.RLock()
	handler := t.stateHandler
	t.mu.RUnlock()

	t.log.Info("reconnecting to MQTT broker")

	if handler != nil {
		handler(t, transport.EventReconnecting)
	}
}

func randomString(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.IntN(len(alphabet))]
	}
	return string(b)
}
