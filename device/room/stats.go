package room

import "encoding/binary"

// ServerStatsSize is the wire size of the ServerStats struct (52 bytes).
// This must match the firmware's ServerStats struct layout exactly.
const ServerStatsSize = 52

// ServerStats mirrors the firmware's ServerStats struct (52 bytes, little-endian).
// It is serialized as a flat binary blob in GET_STATUS responses.
type ServerStats struct {
	BattMilliVolts   uint16 // Offset 0:  battery voltage in millivolts
	CurrTxQueueLen   uint16 // Offset 2:  pending outbound packets
	NoiseFloor       int16  // Offset 4:  noise floor in dBm
	LastRSSI         int16  // Offset 6:  last RSSI in dBm
	NPacketsRecv     uint32 // Offset 8:  total received packets
	NPacketsSent     uint32 // Offset 12: total sent packets
	TotalAirTimeSecs uint32 // Offset 16: cumulative airtime in seconds
	TotalUpTimeSecs  uint32 // Offset 20: cumulative uptime in seconds
	NSentFlood       uint32 // Offset 24: flood-routed packets sent
	NSentDirect      uint32 // Offset 28: direct-routed packets sent
	NRecvFlood       uint32 // Offset 32: flood-routed packets received
	NRecvDirect      uint32 // Offset 36: direct-routed packets received
	ErrEvents        uint16 // Offset 40: error event counter
	LastSNR          int16  // Offset 42: last SNR × 4 (multiply by 0.25 for dB)
	NDirectDups      uint16 // Offset 44: direct route duplicate count
	NFloodDups       uint16 // Offset 46: flood route duplicate count
	NPosted          uint16 // Offset 48: posts added to server
	NPostPush        uint16 // Offset 50: posts pushed to clients
}

// MarshalBinary serializes the stats to a 52-byte little-endian blob
// matching the firmware's memcpy layout.
func (s *ServerStats) MarshalBinary() []byte {
	data := make([]byte, ServerStatsSize)
	binary.LittleEndian.PutUint16(data[0:2], s.BattMilliVolts)
	binary.LittleEndian.PutUint16(data[2:4], s.CurrTxQueueLen)
	binary.LittleEndian.PutUint16(data[4:6], uint16(s.NoiseFloor))
	binary.LittleEndian.PutUint16(data[6:8], uint16(s.LastRSSI))
	binary.LittleEndian.PutUint32(data[8:12], s.NPacketsRecv)
	binary.LittleEndian.PutUint32(data[12:16], s.NPacketsSent)
	binary.LittleEndian.PutUint32(data[16:20], s.TotalAirTimeSecs)
	binary.LittleEndian.PutUint32(data[20:24], s.TotalUpTimeSecs)
	binary.LittleEndian.PutUint32(data[24:28], s.NSentFlood)
	binary.LittleEndian.PutUint32(data[28:32], s.NSentDirect)
	binary.LittleEndian.PutUint32(data[32:36], s.NRecvFlood)
	binary.LittleEndian.PutUint32(data[36:40], s.NRecvDirect)
	binary.LittleEndian.PutUint16(data[40:42], s.ErrEvents)
	binary.LittleEndian.PutUint16(data[42:44], uint16(s.LastSNR))
	binary.LittleEndian.PutUint16(data[44:46], s.NDirectDups)
	binary.LittleEndian.PutUint16(data[46:48], s.NFloodDups)
	binary.LittleEndian.PutUint16(data[48:50], s.NPosted)
	binary.LittleEndian.PutUint16(data[50:52], s.NPostPush)
	return data
}

// StatsProvider supplies server statistics for GET_STATUS responses.
// Implementations populate the ServerStats struct from whatever data sources
// are available (hardware, counters, etc.).
type StatsProvider interface {
	// GetStats returns the current server statistics.
	GetStats() ServerStats
}

// TelemetryProvider supplies CayenneLPP-encoded telemetry for GET_TELEMETRY responses.
// The permMask controls which sensor categories to include (firmware uses
// TELEM_PERM_BASE=0x01, TELEM_PERM_LOCATION=0x02, TELEM_PERM_ENVIRONMENT=0x04).
type TelemetryProvider interface {
	// GetTelemetry returns CayenneLPP-encoded telemetry data.
	// permMask is a bitmask of which sensor categories to query.
	// At minimum, battery voltage (channel 1) should always be included.
	GetTelemetry(permMask uint8) []byte
}
