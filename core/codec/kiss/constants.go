// Package kiss implements the MeshCore KISS TNC protocol: standard KA9Q/K3MC
// KISS serial framing plus the MeshCore SetHardware (0x06) extensions that carry
// crypto, radio control, and telemetry.
//
// The framing here is unrelated to the two other MeshCore stream protocols. The
// companion serial protocol (core/codec/serial) uses a length-prefixed header,
// and the RS232 radio bridge (core/codec/rs232.go) uses a magic number with a
// Fletcher-16 checksum. KISS uses byte stuffing with no length field and no
// checksum, so frame boundaries come solely from the FEND delimiter.
//
// Everything in this package is stateless wire encoding. transport/kiss drives
// it as a host talking to a modem; device/kiss drives it as the modem.
package kiss

// Framing bytes, per the KISS specification.
const (
	// FEND delimits frames. It appears at both ends of every frame.
	FEND = 0xC0
	// FESC introduces an escape pair, replacing a literal FEND or FESC.
	FESC = 0xDB
	// TFEND follows FESC to mean a literal FEND byte.
	TFEND = 0xDC
	// TFESC follows FESC to mean a literal FESC byte.
	TFESC = 0xDD
)

// Frame size limits. These mirror the firmware's KissModem.h.
const (
	// MaxFrameSize is the largest unescaped frame the modem will accept,
	// counting the type byte and everything after it. Escaping can up to double
	// the bytes actually on the wire.
	MaxFrameSize = 512

	// MaxPacketSize bounds the payload of a data frame. It matches the firmware
	// MAX_TRANS_UNIT, so it is the largest mesh packet that fits on air. Data
	// frames carrying more are silently dropped by the modem.
	MaxPacketSize = 255

	// MaxHardwarePayloadSize bounds the data following a SetHardware
	// sub-command byte. A SetHardware frame spends two of its bytes on the type
	// byte and the sub-command, and the rest is payload.
	MaxHardwarePayloadSize = MaxFrameSize - 2
)

// KISS type-byte command codes, the low nibble of the type byte. The high
// nibble is the port number, which is always 0 on a single-port TNC; frames
// arriving on any other port are ignored.
const (
	// CmdData carries a raw packet in either direction. Host to modem it queues
	// a transmission; modem to host it reports a reception.
	CmdData = 0x00
	// CmdTxDelay sets the transmitter keyup delay in 10ms units.
	CmdTxDelay = 0x01
	// CmdPersistence sets the CSMA persistence parameter, 0-255.
	CmdPersistence = 0x02
	// CmdSlotTime sets the CSMA slot interval in 10ms units.
	CmdSlotTime = 0x03
	// CmdTxTail sets the post-transmission hold time in 10ms units.
	CmdTxTail = 0x04
	// CmdFullDuplex selects duplex mode; nonzero disables CSMA.
	CmdFullDuplex = 0x05
	// CmdSetHardware carries a MeshCore extension sub-command.
	CmdSetHardware = 0x06
	// CmdReturn asks the TNC to leave KISS mode. MeshCore treats it as a no-op.
	CmdReturn = 0xFF
)

// Defaults the modem starts with for the CSMA and timing parameters.
const (
	DefaultTxDelay     = 50 // 500ms
	DefaultPersistence = 63
	DefaultSlotTime    = 10 // 100ms
	DefaultTxTail      = 0
)

// FirmwareVersion is the value the modem reports in a Version response. It is
// the KISS modem's own protocol version, not the mesh FIRMWARE_VER_CODE.
const FirmwareVersion = 1

// SetHardware request sub-commands, sent by the host as the first byte of a
// CmdSetHardware frame's data.
const (
	HWCmdGetIdentity     = 0x01 // no data; replies HWRespIdentity
	HWCmdGetRandom       = 0x02 // length(1), 1-64
	HWCmdVerifySignature = 0x03 // pubkey(32) + signature(64) + message
	HWCmdSignData        = 0x04 // message to sign
	HWCmdEncryptData     = 0x05 // shared secret(32) + plaintext
	HWCmdDecryptData     = 0x06 // shared secret(32) + mac(2) + ciphertext
	HWCmdKeyExchange     = 0x07 // remote pubkey(32)
	HWCmdHash            = 0x08 // data to hash
	HWCmdSetRadio        = 0x09 // freq(4) + bw(4) + sf(1) + cr(1)
	HWCmdSetTxPower      = 0x0A // dBm(1)
	HWCmdGetRadio        = 0x0B // no data
	HWCmdGetTxPower      = 0x0C // no data
	HWCmdGetCurrentRssi  = 0x0D // no data
	HWCmdIsChannelBusy   = 0x0E // no data
	HWCmdGetAirtime      = 0x0F // packet length(1)
	HWCmdGetNoiseFloor   = 0x10 // no data
	HWCmdGetVersion      = 0x11 // no data
	HWCmdGetStats        = 0x12 // no data
	HWCmdGetBattery      = 0x13 // no data
	HWCmdGetMCUTemp      = 0x14 // no data
	HWCmdGetSensors      = 0x15 // permission mask(1)
	HWCmdGetDeviceName   = 0x16 // no data
	HWCmdPing            = 0x17 // no data
	HWCmdReboot          = 0x18 // no data
	HWCmdSetSignalReport = 0x19 // enable(1)
	HWCmdGetSignalReport = 0x1A // no data
)

// SetHardware response sub-commands. Every reply to a request uses the request
// code with the high bit set, which HWResponseFor computes. The generic and
// unsolicited codes live in the 0xF0 range instead, outside that mapping.
const (
	HWRespIdentity     = HWCmdGetIdentity | 0x80     // 0x81
	HWRespRandom       = HWCmdGetRandom | 0x80       // 0x82
	HWRespVerify       = HWCmdVerifySignature | 0x80 // 0x83
	HWRespSignature    = HWCmdSignData | 0x80        // 0x84
	HWRespEncrypted    = HWCmdEncryptData | 0x80     // 0x85
	HWRespDecrypted    = HWCmdDecryptData | 0x80     // 0x86
	HWRespSharedSecret = HWCmdKeyExchange | 0x80     // 0x87
	HWRespHash         = HWCmdHash | 0x80            // 0x88
	HWRespRadio        = HWCmdGetRadio | 0x80        // 0x8B
	HWRespTxPower      = HWCmdGetTxPower | 0x80      // 0x8C
	HWRespCurrentRssi  = HWCmdGetCurrentRssi | 0x80  // 0x8D
	HWRespChannelBusy  = HWCmdIsChannelBusy | 0x80   // 0x8E
	HWRespAirtime      = HWCmdGetAirtime | 0x80      // 0x8F
	HWRespNoiseFloor   = HWCmdGetNoiseFloor | 0x80   // 0x90
	HWRespVersion      = HWCmdGetVersion | 0x80      // 0x91
	HWRespStats        = HWCmdGetStats | 0x80        // 0x92
	HWRespBattery      = HWCmdGetBattery | 0x80      // 0x93
	HWRespMCUTemp      = HWCmdGetMCUTemp | 0x80      // 0x94
	HWRespSensors      = HWCmdGetSensors | 0x80      // 0x95
	HWRespDeviceName   = HWCmdGetDeviceName | 0x80   // 0x96
	HWRespPong         = HWCmdPing | 0x80            // 0x97
	HWRespSignalReport = HWCmdGetSignalReport | 0x80 // 0x9A

	// HWRespOK acknowledges a request that returns no data (SetRadio,
	// SetTxPower, Reboot).
	HWRespOK = 0xF0
	// HWRespError carries a single HWErr* code.
	HWRespError = 0xF1
	// HWRespTxDone is unsolicited, sent when a transmission finishes.
	HWRespTxDone = 0xF8
	// HWRespRxMeta is unsolicited, sent immediately after the data frame it
	// describes.
	HWRespRxMeta = 0xF9
)

// Error codes carried by an HWRespError frame.
const (
	HWErrInvalidLength = 0x01 // request data too short
	HWErrInvalidParam  = 0x02 // parameter out of range
	HWErrNoCallback    = 0x03 // feature not available on this hardware
	HWErrMacFailed     = 0x04 // MAC verification failed
	HWErrUnknownCmd    = 0x05 // unrecognized sub-command
	HWErrEncryptFailed = 0x06 // encryption failed
	HWErrTxBusy        = 0x07 // radio busy, or host output queue full
)

// Sensor permission bits for HWCmdGetSensors. They match the firmware's
// TELEM_PERM_* mask used elsewhere in MeshCore telemetry.
const (
	SensorPermBase        = 0x01 // battery
	SensorPermLocation    = 0x02 // GPS
	SensorPermEnvironment = 0x04 // temperature, humidity, pressure
	SensorPermAll         = SensorPermBase | SensorPermLocation | SensorPermEnvironment
)

// Payload sizes for the crypto sub-commands.
const (
	PubKeySize    = 32
	SignatureSize = 64
	CipherMACSize = 2
	HashSize      = 32
	// MaxRandomSize is the largest GetRandom request the modem will honor.
	MaxRandomSize = 64
)

// TypeByte packs a port and command into a KISS type byte.
func TypeByte(port, cmd uint8) byte {
	return byte(port<<4) | byte(cmd&0x0F)
}

// SplitTypeByte separates a KISS type byte into its port and command nibbles.
// CmdReturn (0xFF) does not follow the nibble split and must be checked against
// the whole byte before calling this.
func SplitTypeByte(b byte) (port, cmd uint8) {
	return uint8(b>>4) & 0x0F, uint8(b) & 0x0F
}

// HWResponseFor returns the response sub-command that answers a request
// sub-command. Only the 0x01-0x1A request range maps this way; the generic and
// unsolicited codes are constants of their own.
func HWResponseFor(subCmd uint8) uint8 { return subCmd | 0x80 }
