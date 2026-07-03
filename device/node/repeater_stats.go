package node

import "encoding/binary"

// RepeaterStatsSize is the wire size of RepeaterStats (56 bytes, little-endian).
// It must match the firmware's RepeaterStats struct layout exactly.
const RepeaterStatsSize = 56

// RepeaterStats mirrors the firmware's RepeaterStats struct returned by
// REQ_TYPE_GET_STATUS. It shares a 48-byte prefix with the room server's
// ServerStats, then diverges: a repeater reports total RX airtime and receive
// errors where the room reports post counts.
//
// Radio/hardware fields (battery, noise floor, RSSI/SNR, airtime, receive
// errors, TX queue length) are left zero on a transport-attached node.
type RepeaterStats struct {
	BattMilliVolts     uint16 // 0
	CurrTxQueueLen     uint16 // 2
	NoiseFloor         int16  // 4
	LastRSSI           int16  // 6
	NPacketsRecv       uint32 // 8
	NPacketsSent       uint32 // 12
	TotalAirTimeSecs   uint32 // 16
	TotalUpTimeSecs    uint32 // 20
	NSentFlood         uint32 // 24
	NSentDirect        uint32 // 28
	NRecvFlood         uint32 // 32
	NRecvDirect        uint32 // 36
	ErrEvents          uint16 // 40
	LastSNR            int16  // 42 (x4)
	NDirectDups        uint16 // 44
	NFloodDups         uint16 // 46
	TotalRxAirTimeSecs uint32 // 48
	NRecvErrors        uint32 // 52
}

// MarshalBinary serializes the stats to a 56-byte little-endian blob matching
// the firmware's memcpy layout.
func (s *RepeaterStats) MarshalBinary() []byte {
	b := make([]byte, RepeaterStatsSize)
	binary.LittleEndian.PutUint16(b[0:2], s.BattMilliVolts)
	binary.LittleEndian.PutUint16(b[2:4], s.CurrTxQueueLen)
	binary.LittleEndian.PutUint16(b[4:6], uint16(s.NoiseFloor))
	binary.LittleEndian.PutUint16(b[6:8], uint16(s.LastRSSI))
	binary.LittleEndian.PutUint32(b[8:12], s.NPacketsRecv)
	binary.LittleEndian.PutUint32(b[12:16], s.NPacketsSent)
	binary.LittleEndian.PutUint32(b[16:20], s.TotalAirTimeSecs)
	binary.LittleEndian.PutUint32(b[20:24], s.TotalUpTimeSecs)
	binary.LittleEndian.PutUint32(b[24:28], s.NSentFlood)
	binary.LittleEndian.PutUint32(b[28:32], s.NSentDirect)
	binary.LittleEndian.PutUint32(b[32:36], s.NRecvFlood)
	binary.LittleEndian.PutUint32(b[36:40], s.NRecvDirect)
	binary.LittleEndian.PutUint16(b[40:42], s.ErrEvents)
	binary.LittleEndian.PutUint16(b[42:44], uint16(s.LastSNR))
	binary.LittleEndian.PutUint16(b[44:46], s.NDirectDups)
	binary.LittleEndian.PutUint16(b[46:48], s.NFloodDups)
	binary.LittleEndian.PutUint32(b[48:52], s.TotalRxAirTimeSecs)
	binary.LittleEndian.PutUint32(b[52:56], s.NRecvErrors)
	return b
}
