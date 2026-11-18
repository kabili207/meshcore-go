package companion

import (
	"bytes"

	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/router"
)

// Settings are the app-configurable values firmware keeps in its preferences
// file. The session-only flood scope override is not among them.
type Settings struct {
	Name             string              `json:"name"`
	AdvLat           int32               `json:"adv_lat"` // degrees x1e6
	AdvLon           int32               `json:"adv_lon"`
	AdvLocPolicy     uint8               `json:"adv_loc_policy"`
	RadioFreqKHz     uint32              `json:"radio_freq_khz"`
	RadioBwHz        uint32              `json:"radio_bw_hz"`
	RadioSF          uint8               `json:"radio_sf"`
	RadioCR          uint8               `json:"radio_cr"`
	TxPower          uint8               `json:"tx_power"`
	RxDelay          uint32              `json:"rx_delay"`
	AirtimeFactor    uint32              `json:"airtime_factor"`
	TZOffset         int8                `json:"tz_offset"`
	AutoaddConfig    uint8               `json:"autoadd_config"`
	AutoaddMaxHops   uint8               `json:"autoadd_max_hops"`
	DefaultScopeName string              `json:"default_scope_name"`
	DefaultScopeKey  router.TransportKey `json:"default_scope_key"`
}

// Channel is one slot of the group channel table. A cleared slot is saved too,
// so a deleted Public channel stays deleted.
type Channel struct {
	Index  uint8
	Name   string
	Secret []byte
}

// Persistence is an optional durable backend for the server's settings and
// channels. Its methods run with the server's lock held, so they should be quick.
type Persistence interface {
	// LoadSettings overlays saved values onto s, leaving any field without a
	// saved value unchanged.
	LoadSettings(s *Settings) error
	SaveSettings(s *Settings) error
	LoadChannels() ([]Channel, error)
	SaveChannel(ch Channel) error
}

// restore applies persisted state during NewServer. Whatever is configured at
// that point is then saved, so Identity only provides first-run values. If
// loading fails, persistence is turned off rather than overwriting saved state
// with defaults.
func (s *Server) restore() {
	if s.persistence == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	settings := s.settingsLocked()
	err := s.persistence.LoadSettings(&settings)
	var channels []Channel
	if err == nil {
		channels, err = s.persistence.LoadChannels()
	}
	if err != nil {
		s.log.Error("failed to load saved settings, changes will not be saved", "error", err)
		s.persistence = nil
		return
	}

	s.applySettingsLocked(&settings)
	for _, ch := range channels {
		if int(ch.Index) < len(s.channels) && (len(ch.Secret) == 0 || len(ch.Secret) == channelSecretLen) {
			s.channels[ch.Index] = channelEntry{name: ch.Name, secret: ch.Secret}
		}
	}
	// CompanionNode registers Public itself, so it has to be undone if deleted.
	if !s.keyInUseLocked(crypto.DefaultChannelKey) {
		s.node.RemoveChannel(crypto.DefaultChannelKey)
	}
	for _, ch := range s.channels {
		if ch.active() {
			s.node.AddChannel(ch.secret)
		}
	}
	if !s.defaultScopeKey.IsNull() {
		s.applyFloodScopeLocked()
	}
	s.saveSettingsLocked()
}

func (s *Server) settingsLocked() Settings {
	return Settings{
		Name:             s.name,
		AdvLat:           s.advLat,
		AdvLon:           s.advLon,
		AdvLocPolicy:     s.advLocPolicy,
		RadioFreqKHz:     s.radioFreqKHz,
		RadioBwHz:        s.radioBwHz,
		RadioSF:          s.radioSF,
		RadioCR:          s.radioCR,
		TxPower:          s.txPower,
		RxDelay:          s.rxDelay,
		AirtimeFactor:    s.airtimeFactor,
		TZOffset:         s.tzOffset,
		AutoaddConfig:    s.autoaddConfig,
		AutoaddMaxHops:   s.autoaddMaxHops,
		DefaultScopeName: s.defaultScopeName,
		DefaultScopeKey:  s.defaultScopeKey,
	}
}

func (s *Server) applySettingsLocked(v *Settings) {
	s.name = v.Name
	s.advLat, s.advLon, s.advLocPolicy = v.AdvLat, v.AdvLon, v.AdvLocPolicy
	s.radioFreqKHz, s.radioBwHz, s.radioSF, s.radioCR = v.RadioFreqKHz, v.RadioBwHz, v.RadioSF, v.RadioCR
	s.txPower = v.TxPower
	s.rxDelay, s.airtimeFactor = v.RxDelay, v.AirtimeFactor
	s.tzOffset = v.TZOffset
	s.autoaddConfig, s.autoaddMaxHops = v.AutoaddConfig, v.AutoaddMaxHops
	s.defaultScopeName, s.defaultScopeKey = v.DefaultScopeName, v.DefaultScopeKey
}

func (s *Server) saveSettingsLocked() {
	if s.persistence == nil {
		return
	}
	settings := s.settingsLocked()
	if err := s.persistence.SaveSettings(&settings); err != nil {
		s.log.Warn("failed to save settings", "error", err)
	}
}

func (s *Server) saveChannelLocked(idx uint8) {
	if s.persistence == nil {
		return
	}
	ch := s.channels[idx]
	err := s.persistence.SaveChannel(Channel{Index: idx, Name: ch.name, Secret: bytes.Clone(ch.secret)})
	if err != nil {
		s.log.Warn("failed to save channel", "index", idx, "error", err)
	}
}
