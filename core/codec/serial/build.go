package serial

import "encoding/binary"

// Advertised node/adv types reported in SELF_INFO and Contact frames. These
// mirror the firmware ADV_TYPE_* values (and codec.NodeType*).
const (
	AdvTypeNone     = 0
	AdvTypeChat     = 1
	AdvTypeRepeater = 2
	AdvTypeRoom     = 3
	AdvTypeSensor   = 4
)

// CompanionFirmwareVerCode is the FIRMWARE_VER_CODE the device reports as byte 1
// of DEVICE_INFO. 13 corresponds to firmware v1.16.0 and gates which features
// the phone apps enable.
const CompanionFirmwareVerCode = 13

// Response payload builders for the companion protocol (device -> app). Each
// returns a payload whose first byte is the response code; wrap it with
// EncodeFrame(FrameNodeToApp, ...) before writing to the stream. Byte layouts
// mirror the firmware's companion_radio serializers (MyMesh.cpp) and are what
// meshcore.js / MeshMonitor decode. All multi-byte integers are little-endian.

// EncodeOK builds a RESP_CODE_OK payload (a single byte).
func EncodeOK() []byte { return []byte{RespCodeOK} }

// EncodeErr builds a RESP_CODE_ERR payload carrying one of the ErrCode* values.
func EncodeErr(errCode uint8) []byte { return []byte{RespCodeErr, errCode} }

// EncodeCurrTime builds a RESP_CODE_CURR_TIME payload (reply to
// CMD_GET_DEVICE_TIME): [code][epoch uint32 LE].
func EncodeCurrTime(epochSecs uint32) []byte {
	b := make([]byte, 5)
	b[0] = RespCodeCurrTime
	binary.LittleEndian.PutUint32(b[1:], epochSecs)
	return b
}

// EncodeContactsStart builds a RESP_CODE_CONTACTS_START payload announcing how
// many RESP_CODE_CONTACT frames follow: [code][count uint32 LE].
func EncodeContactsStart(count uint32) []byte {
	b := make([]byte, 5)
	b[0] = RespCodeContactsStart
	binary.LittleEndian.PutUint32(b[1:], count)
	return b
}

// EncodeEndOfContacts builds a RESP_CODE_END_OF_CONTACTS payload. mostRecentLastmod
// is the newest contact lastmod the client should save as its next "since".
func EncodeEndOfContacts(mostRecentLastmod uint32) []byte {
	b := make([]byte, 5)
	b[0] = RespCodeEndOfContacts
	binary.LittleEndian.PutUint32(b[1:], mostRecentLastmod)
	return b
}

// SelfInfo is the RESP_CODE_SELF_INFO payload, the reply to CMD_APP_START.
// Fixed part is 58 bytes; Name is appended raw (UTF-8, no terminator).
type SelfInfo struct {
	// AdvType is the node's advertised role (1 chat, 2 repeater, 3 room). A
	// companion server reports 1.
	AdvType    uint8
	TxPower    uint8
	MaxTxPower uint8
	PublicKey  [32]byte
	// AdvLat / AdvLon are advertised coordinates as fixed-point degrees x1e6.
	AdvLat int32
	AdvLon int32
	// MultiAcks, AdvLocPolicy, TelemetryMode ((env<<4)|(loc<<2)|base), and
	// ManualAddContacts are firmware preference bytes; zero is a safe default.
	MultiAcks         uint8
	AdvLocPolicy      uint8
	TelemetryMode     uint8
	ManualAddContacts uint8
	// RadioFreq is in kHz (freq_MHz*1000, e.g. 915.0 MHz -> 915000).
	RadioFreq uint32
	// RadioBw is in Hz (bw_kHz*1000, e.g. 250 kHz -> 250000).
	RadioBw uint32
	RadioSf uint8
	RadioCr uint8
	Name    string
}

// Encode serializes the self-info payload (response code byte first).
func (s *SelfInfo) Encode() []byte {
	buf := make([]byte, 58+len(s.Name))
	buf[0] = RespCodeSelfInfo
	buf[1] = s.AdvType
	buf[2] = s.TxPower
	buf[3] = s.MaxTxPower
	copy(buf[4:36], s.PublicKey[:])
	binary.LittleEndian.PutUint32(buf[36:40], uint32(s.AdvLat))
	binary.LittleEndian.PutUint32(buf[40:44], uint32(s.AdvLon))
	buf[44] = s.MultiAcks
	buf[45] = s.AdvLocPolicy
	buf[46] = s.TelemetryMode
	buf[47] = s.ManualAddContacts
	binary.LittleEndian.PutUint32(buf[48:52], s.RadioFreq)
	binary.LittleEndian.PutUint32(buf[52:56], s.RadioBw)
	buf[56] = s.RadioSf
	buf[57] = s.RadioCr
	copy(buf[58:], s.Name)
	return buf
}

// deviceInfoSize is the fixed RESP_CODE_DEVICE_INFO payload length (MyMesh.cpp):
// code + ver + max_contacts/2 + max_channels + ble_pin(4) + build_date(12) +
// manufacturer(40) + firmware_version(20) + client_repeat + path_hash_mode.
const deviceInfoSize = 1 + 1 + 1 + 1 + 4 + 12 + 40 + 20 + 1 + 1 // 82

// DeviceInfo is the RESP_CODE_DEVICE_INFO payload, the reply to CMD_DEVICE_QUERY.
// The layout is fixed-width: the official app reads FirmwareVersion at offset 60,
// so all fields must sit at their firmware offsets (a compact form is rejected).
type DeviceInfo struct {
	// FirmwareVerCode is the protocol/firmware version code (13 for v1.16.0).
	FirmwareVerCode uint8
	// MaxContactsDiv2 is max_contacts/2; MaxGroupChannels is the channel count.
	MaxContactsDiv2  uint8
	MaxGroupChannels uint8
	BLEPin           uint32
	// BuildDate ("6 Jun 2026") goes in a fixed 12-byte NUL-terminated field.
	BuildDate string
	// Manufacturer/model goes in a fixed 40-byte field at offset 20.
	Manufacturer string
	// FirmwareVersion ("v1.16.0") goes in a fixed 20-byte field at offset 60.
	FirmwareVersion string
	// ClientRepeat (v9+) and PathHashMode (v10+) are the two trailing bytes.
	ClientRepeat uint8
	PathHashMode uint8
}

// Encode serializes the device-info payload (response code byte first), 82 bytes.
func (d *DeviceInfo) Encode() []byte {
	buf := make([]byte, deviceInfoSize)
	buf[0] = RespCodeDeviceInfo
	buf[1] = d.FirmwareVerCode
	buf[2] = d.MaxContactsDiv2
	buf[3] = d.MaxGroupChannels
	binary.LittleEndian.PutUint32(buf[4:8], d.BLEPin)
	writeCString(buf[8:20], d.BuildDate)
	writeCString(buf[20:60], d.Manufacturer)
	writeCString(buf[60:80], d.FirmwareVersion)
	buf[80] = d.ClientRepeat
	buf[81] = d.PathHashMode
	return buf
}

// contactFrameSize is the fixed RESP_CODE_CONTACT payload length (MyMesh.cpp
// writeContactRespFrame): code + pubkey(32) + type + flags + out_path_len +
// out_path(64) + name(32) + 4x uint32.
const contactFrameSize = 1 + 32 + 1 + 1 + 1 + 64 + 32 + 4 + 4 + 4 + 4 // 148

// Contact is the RESP_CODE_CONTACT payload (one per known contact, streamed
// between ContactsStart and EndOfContacts). Also the CMD_ADD_UPDATE_CONTACT
// layout inbound.
type Contact struct {
	PublicKey [32]byte
	Type      uint8
	Flags     uint8
	// OutPathLen is the cached out-path hop count; 0xFF means the route is
	// unknown (OUT_PATH_UNKNOWN).
	OutPathLen uint8
	// OutPath holds up to 64 hop-hash bytes; zero-padded to 64 on the wire.
	OutPath []byte
	Name    string
	// LastAdvert and LastMod are epoch seconds; GPSLat/GPSLon are fixed-point
	// degrees x1e6.
	LastAdvert uint32
	GPSLat     int32
	GPSLon     int32
	LastMod    uint32
}

// Encode serializes the contact payload as a RESP_CODE_CONTACT frame (148 bytes).
func (c *Contact) Encode() []byte { return c.EncodeWithCode(RespCodeContact) }

// EncodeWithCode serializes the contact payload with an explicit leading code.
// PUSH_CODE_NEW_ADVERT reuses this exact 148-byte layout.
func (c *Contact) EncodeWithCode(code uint8) []byte {
	buf := make([]byte, contactFrameSize)
	buf[0] = code
	copy(buf[1:33], c.PublicKey[:])
	buf[33] = c.Type
	buf[34] = c.Flags
	buf[35] = c.OutPathLen
	copy(buf[36:100], c.OutPath) // truncates to 64, zero-pads the rest
	writeCString(buf[100:132], c.Name)
	binary.LittleEndian.PutUint32(buf[132:136], c.LastAdvert)
	binary.LittleEndian.PutUint32(buf[136:140], uint32(c.GPSLat))
	binary.LittleEndian.PutUint32(buf[140:144], uint32(c.GPSLon))
	binary.LittleEndian.PutUint32(buf[144:148], c.LastMod)
	return buf
}

// EncodeNoMoreMessages builds a RESP_CODE_NO_MORE_MESSAGES payload (single
// byte), the reply to CMD_SYNC_NEXT_MESSAGE when the offline queue is empty.
func EncodeNoMoreMessages() []byte { return []byte{RespCodeNoMoreMessages} }

// sent_type values for the RESP_CODE_SENT reply.
const (
	SentTypeDirect = 0
	SentTypeFlood  = 1
)

// EncodeSent builds a RESP_CODE_SENT payload: [code][sent_type][expected_ack
// u32][est_timeout_ms u32]. The app later matches a PUSH_CODE_SEND_CONFIRMED
// whose ack_code equals expectedAck.
//
// Reply RESP_CODE_SENT ONLY for the "send to a remote node and await an ACK"
// commands: SEND_TXT_MSG, SEND_LOGIN, SEND_ANON_REQ, SEND_STATUS_REQ,
// SEND_PATH_DISCOVERY_REQ, SEND_TELEMETRY_REQ (to a contact), SEND_BINARY_REQ,
// and SEND_TRACE_PATH. Broadcast/raw sends and every config write instead reply
// with a bare RESP_CODE_OK (EncodeOK) and produce no confirmation, e.g.
// SEND_CHANNEL_TXT_MSG, SEND_CHANNEL_DATA, SEND_SELF_ADVERT, SEND_RAW_DATA,
// SEND_CONTROL_DATA, SEND_RAW_PACKET, and the SET_* commands. This distinction
// is firmware-exact: the official app ignores a send it does not see
// acknowledged with the reply type it expects (a SENT frame for a channel send
// leaves the message unaccepted until the app reloads).
func EncodeSent(sentType uint8, expectedAck, estTimeoutMs uint32) []byte {
	b := make([]byte, 10)
	b[0] = RespCodeSent
	b[1] = sentType
	binary.LittleEndian.PutUint32(b[2:6], expectedAck)
	binary.LittleEndian.PutUint32(b[6:10], estTimeoutMs)
	return b
}

// EncodeMsgWaiting builds a PUSH_CODE_MSG_WAITING payload (single byte). It
// tells the app to drain the queue with CMD_SYNC_NEXT_MESSAGE.
func EncodeMsgWaiting() []byte { return []byte{PushCodeMsgWaiting} }

// EncodeSendConfirmed builds a PUSH_CODE_SEND_CONFIRMED payload:
// [code][ack_code u32][round_trip_ms u32]. ackCode must equal the expectedAck
// reported in the matching RESP_CODE_SENT.
func EncodeSendConfirmed(ackCode, roundTripMs uint32) []byte {
	b := make([]byte, 9)
	b[0] = PushCodeSendConfirmed
	binary.LittleEndian.PutUint32(b[1:5], ackCode)
	binary.LittleEndian.PutUint32(b[5:9], roundTripMs)
	return b
}

// EncodeContactMsgRecv builds an incoming direct-message frame drained by
// CMD_SYNC_NEXT_MESSAGE. When v3 is true it uses RESP_CODE_CONTACT_MSG_RECV_V3
// (adds an SNR byte and two reserved bytes); otherwise RESP_CODE_CONTACT_MSG_RECV.
// senderPrefix is the first 6 bytes of the sender's public key; pathLen is the
// hop count (0xFF for a direct delivery).
func EncodeContactMsgRecv(v3 bool, snr int8, senderPrefix []byte, pathLen, txtType uint8, senderTS uint32, text string) []byte {
	if v3 {
		b := make([]byte, 16+len(text))
		b[0] = RespCodeContactMsgRecvV3
		b[1] = byte(snr)
		// b[2], b[3] reserved (0)
		copy(b[4:10], senderPrefix)
		b[10] = pathLen
		b[11] = txtType
		binary.LittleEndian.PutUint32(b[12:16], senderTS)
		copy(b[16:], text)
		return b
	}
	b := make([]byte, 13+len(text))
	b[0] = RespCodeContactMsgRecv
	copy(b[1:7], senderPrefix)
	b[7] = pathLen
	b[8] = txtType
	binary.LittleEndian.PutUint32(b[9:13], senderTS)
	copy(b[13:], text)
	return b
}

// EncodeChannelMsgRecv builds an incoming group-message frame drained by
// CMD_SYNC_NEXT_MESSAGE. When v3 is true it uses RESP_CODE_CHANNEL_MSG_RECV_V3
// (adds an SNR byte and two reserved bytes); otherwise RESP_CODE_CHANNEL_MSG_RECV.
func EncodeChannelMsgRecv(v3 bool, snr int8, channelIdx, pathLen, txtType uint8, senderTS uint32, text string) []byte {
	if v3 {
		b := make([]byte, 11+len(text))
		b[0] = RespCodeChannelMsgRecvV3
		b[1] = byte(snr)
		// b[2], b[3] reserved (0)
		b[4] = channelIdx
		b[5] = pathLen
		b[6] = txtType
		binary.LittleEndian.PutUint32(b[7:11], senderTS)
		copy(b[11:], text)
		return b
	}
	b := make([]byte, 8+len(text))
	b[0] = RespCodeChannelMsgRecv
	b[1] = channelIdx
	b[2] = pathLen
	b[3] = txtType
	binary.LittleEndian.PutUint32(b[4:8], senderTS)
	copy(b[8:], text)
	return b
}

// EncodeBattAndStorage builds a RESP_CODE_BATT_AND_STORAGE payload (reply to
// CMD_GET_BATT_AND_STORAGE): [code][battery_mV u16][used_KB u32][total_KB u32].
// Storage values are in kilobytes.
func EncodeBattAndStorage(batteryMilliVolts uint16, storageUsedKB, storageTotalKB uint32) []byte {
	b := make([]byte, 11)
	b[0] = RespCodeBattAndStorage
	binary.LittleEndian.PutUint16(b[1:3], batteryMilliVolts)
	binary.LittleEndian.PutUint32(b[3:7], storageUsedKB)
	binary.LittleEndian.PutUint32(b[7:11], storageTotalKB)
	return b
}

// EncodeCustomVars builds a RESP_CODE_CUSTOM_VARS payload: the code byte
// followed by a comma-separated "name:value" list (empty for no custom vars).
func EncodeCustomVars(vars string) []byte {
	return append([]byte{RespCodeCustomVars}, vars...)
}

// EncodeAutoaddConfig builds a RESP_CODE_AUTOADD_CONFIG payload:
// [code][config][max_hops].
func EncodeAutoaddConfig(config, maxHops uint8) []byte {
	return []byte{RespCodeAutoaddConfig, config, maxHops}
}

// EncodeTuningParams builds a RESP_CODE_TUNING_PARAMS payload (reply to
// CMD_GET_TUNING_PARAMS): [code][rx_delay u32][airtime_factor u32], both x1000.
func EncodeTuningParams(rxDelay, airtimeFactor uint32) []byte {
	b := make([]byte, 9)
	b[0] = RespCodeTuningParams
	binary.LittleEndian.PutUint32(b[1:5], rxDelay)
	binary.LittleEndian.PutUint32(b[5:9], airtimeFactor)
	return b
}

// EncodeStatsCore builds a RESP_CODE_STATS / STATS_TYPE_CORE payload:
// [code][type][battery_mv u16][uptime_secs u32][err_flags u16][queue_len u8].
func EncodeStatsCore(batteryMilliVolts uint16, uptimeSecs uint32, errFlags uint16, queueLen uint8) []byte {
	b := make([]byte, 11)
	b[0] = RespCodeStats
	b[1] = StatsTypeCore
	binary.LittleEndian.PutUint16(b[2:4], batteryMilliVolts)
	binary.LittleEndian.PutUint32(b[4:8], uptimeSecs)
	binary.LittleEndian.PutUint16(b[8:10], errFlags)
	b[10] = queueLen
	return b
}

// EncodeStatsRadio builds a RESP_CODE_STATS / STATS_TYPE_RADIO payload:
// [code][type][noise_floor i16][last_rssi i8][last_snr i8][tx_air_secs u32]
// [rx_air_secs u32]. last_snr is scaled x4 (0.25 dB units).
func EncodeStatsRadio(noiseFloor int16, lastRSSI, lastSNR int8, txAirSecs, rxAirSecs uint32) []byte {
	b := make([]byte, 14)
	b[0] = RespCodeStats
	b[1] = StatsTypeRadio
	binary.LittleEndian.PutUint16(b[2:4], uint16(noiseFloor))
	b[4] = byte(lastRSSI)
	b[5] = byte(lastSNR)
	binary.LittleEndian.PutUint32(b[6:10], txAirSecs)
	binary.LittleEndian.PutUint32(b[10:14], rxAirSecs)
	return b
}

// EncodeStatsPackets builds a RESP_CODE_STATS / STATS_TYPE_PACKETS payload:
// [code][type] followed by seven uint32 counters (recv, sent, sent_flood,
// sent_direct, recv_flood, recv_direct, recv_errors).
func EncodeStatsPackets(recv, sent, sentFlood, sentDirect, recvFlood, recvDirect, recvErrors uint32) []byte {
	b := make([]byte, 30)
	b[0] = RespCodeStats
	b[1] = StatsTypePackets
	binary.LittleEndian.PutUint32(b[2:6], recv)
	binary.LittleEndian.PutUint32(b[6:10], sent)
	binary.LittleEndian.PutUint32(b[10:14], sentFlood)
	binary.LittleEndian.PutUint32(b[14:18], sentDirect)
	binary.LittleEndian.PutUint32(b[18:22], recvFlood)
	binary.LittleEndian.PutUint32(b[22:26], recvDirect)
	binary.LittleEndian.PutUint32(b[26:30], recvErrors)
	return b
}

// EncodeDefaultFloodScope builds a RESP_CODE_DEFAULT_FLOOD_SCOPE payload (reply
// to CMD_GET_DEFAULT_FLOOD_SCOPE). An empty name means no scope is configured
// and the payload is just [code]; otherwise it is [code][name 31-byte
// C-string][key 16 bytes].
func EncodeDefaultFloodScope(name string, key []byte) []byte {
	if name == "" {
		return []byte{RespCodeDefaultFloodScope}
	}
	b := make([]byte, 1+31+16)
	b[0] = RespCodeDefaultFloodScope
	writeCString(b[1:32], name)
	copy(b[32:48], key)
	return b
}

// ChannelInfo is the RESP_CODE_CHANNEL_INFO payload (reply to CMD_GET_CHANNEL):
// [code][index][name 32-byte C-string][secret 16 bytes]. Only 128-bit (16-byte)
// channel secrets are supported.
type ChannelInfo struct {
	Index  uint8
	Name   string
	Secret []byte // truncated/zero-padded to 16 bytes
}

// Encode serializes the channel-info payload (response code byte first), 50 bytes.
func (c *ChannelInfo) Encode() []byte {
	b := make([]byte, 1+1+32+16)
	b[0] = RespCodeChannelInfo
	b[1] = c.Index
	writeCString(b[2:34], c.Name)
	copy(b[34:50], c.Secret)
	return b
}

// EncodeAdvert builds a PUSH_CODE_ADVERT payload ([code][pubkey 32]): a known
// contact was re-heard. A first-seen contact instead uses the full contact
// frame via (*Contact).EncodeWithCode(PushCodeNewAdvert).
func EncodeAdvert(pubKey [32]byte) []byte { return pubKeyPush(PushCodeAdvert, pubKey) }

// EncodePathUpdated builds a PUSH_CODE_PATH_UPDATED payload: a contact's routing
// path changed.
func EncodePathUpdated(pubKey [32]byte) []byte { return pubKeyPush(PushCodePathUpdated, pubKey) }

// EncodeContactDeleted builds a PUSH_CODE_CONTACT_DELETED payload: a contact was
// evicted from a full table.
func EncodeContactDeleted(pubKey [32]byte) []byte { return pubKeyPush(PushCodeContactDeleted, pubKey) }

func pubKeyPush(code byte, pubKey [32]byte) []byte {
	b := make([]byte, 1+32)
	b[0] = code
	copy(b[1:], pubKey[:])
	return b
}

// EncodeContactsFull builds a PUSH_CODE_CONTACTS_FULL payload (single byte).
func EncodeContactsFull() []byte { return []byte{PushCodeContactsFull} }

// writeCString writes s into dst as a fixed-width, NUL-terminated C string. It
// copies at most len(dst)-1 bytes so the field always ends with at least one
// NUL; dst is assumed pre-zeroed (freshly allocated).
func writeCString(dst []byte, s string) {
	n := len(s)
	if n > len(dst)-1 {
		n = len(dst) - 1
	}
	copy(dst[:n], s[:n])
}
