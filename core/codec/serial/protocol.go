// Package serial provides constants and helpers for the MeshCore companion radio
// serial protocol (USB/RS232). These commands are used for communication between
// a host application and a companion radio node.
//
// Note: Some of these commands can also be sent over the mesh network, making
// them relevant for mesh protocol implementations.
package serial

// Command codes sent from host to companion radio.
const (
	CmdAppStart             = 1  // Start application connection
	CmdSendTxtMsg           = 2  // Send text message to contact
	CmdSendChannelTxtMsg    = 3  // Send text message to group channel
	CmdGetContacts          = 4  // Get contact list (with optional 'since' for sync)
	CmdGetDeviceTime        = 5  // Get device RTC time
	CmdSetDeviceTime        = 6  // Set device RTC time
	CmdSendSelfAdvert       = 7  // Trigger self-advertisement
	CmdSetAdvertName        = 8  // Set node advertisement name
	CmdAddUpdateContact     = 9  // Add or update a contact
	CmdSyncNextMessage      = 10 // Get next message from offline queue
	CmdSetRadioParams       = 11 // Set LoRa radio parameters
	CmdSetRadioTxPower      = 12 // Set radio TX power
	CmdResetPath            = 13 // Reset path to contact
	CmdSetAdvertLatLon      = 14 // Set GPS coordinates in advertisement
	CmdRemoveContact        = 15 // Remove a contact
	CmdShareContact         = 16 // Share contact with another node
	CmdExportContact        = 17 // Export contact public key
	CmdImportContact        = 18 // Import contact public key
	CmdReboot               = 19 // Reboot the device
	CmdGetBattAndStorage    = 20 // Get battery and storage info (was CmdGetBatteryVoltage)
	CmdSetTuningParams      = 21 // Set radio tuning parameters
	CmdDeviceQuery          = 22 // Query device info
	CmdExportPrivateKey     = 23 // Export private key (encrypted)
	CmdImportPrivateKey     = 24 // Import private key
	CmdSendRawData          = 25 // Send raw packet data
	CmdSendLogin            = 26 // Send login request
	CmdSendStatusReq        = 27 // Send status request
	CmdHasConnection        = 28 // Check connection status
	CmdLogout               = 29 // Disconnect from node
	CmdGetContactByKey      = 30 // Get contact by public key
	CmdGetChannel           = 31 // Get channel info
	CmdSetChannel           = 32 // Set channel (group) configuration
	CmdSignStart            = 33 // Start message signing
	CmdSignData             = 34 // Sign data chunk
	CmdSignFinish           = 35 // Finish signing
	CmdSendTracePath        = 36 // Send path trace request
	CmdSetDevicePin         = 37 // Set BLE pairing PIN
	CmdSetOtherParams       = 38 // Set other device parameters
	CmdSendTelemetryReq     = 39 // Request telemetry data (deprecated)
	CmdGetCustomVars        = 40 // Get custom variables
	CmdSetCustomVar         = 41 // Set custom variable
	CmdGetAdvertPath        = 42 // Get advertisement path
	CmdGetTuningParams      = 43 // Get tuning parameters
	CmdSendBinaryReq        = 50 // Send binary request
	CmdFactoryReset         = 51 // Factory reset device
	CmdSendPathDiscoveryReq = 52 // Send path discovery request
	CmdSetFloodScopeKey     = 54 // Set flood scope key (v8+, was CmdSetFloodScope)
	CmdSendControlData      = 55 // Send control data (v8+)
	CmdGetStats             = 56 // Get statistics (v8+, second byte is stats type)
	CmdSendAnonReq          = 57 // Send anonymous request
	CmdSetAutoaddConfig     = 58 // Set auto-add contacts config
	CmdGetAutoaddConfig     = 59 // Get auto-add contacts config
	CmdGetAllowedRepeatFreq = 60 // Get allowed repeat frequencies
	CmdSetPathHashMode      = 61 // Set path hash mode
	CmdSendChannelData      = 62 // Send binary data to group channel (v1.15.0+)
	CmdSetDefaultFloodScope = 63 // Set default flood scope (v1.15.0+)
	CmdGetDefaultFloodScope = 64 // Get default flood scope (v1.15.0+)
	CmdSendRawPacket        = 65 // Send a raw mesh packet (v1.16.0+)
)

// Response codes sent from companion radio to host.
const (
	RespCodeOK                = 0  // Success
	RespCodeErr               = 1  // Generic error
	RespCodeContactsStart     = 2  // Start of contact list response
	RespCodeContact           = 3  // Contact entry in list
	RespCodeEndOfContacts     = 4  // End of contact list
	RespCodeSelfInfo          = 5  // Self node info (reply to CmdAppStart)
	RespCodeSent              = 6  // Message sent confirmation
	RespCodeContactMsgRecv    = 7  // Contact message received (ver < 3)
	RespCodeChannelMsgRecv    = 8  // Channel message received (ver < 3)
	RespCodeCurrTime          = 9  // Current device time
	RespCodeNoMoreMessages    = 10 // No more messages in queue
	RespCodeExportContact     = 11 // Exported contact data
	RespCodeBattAndStorage    = 12 // Battery and storage info
	RespCodeDeviceInfo        = 13 // Device information
	RespCodePrivateKey        = 14 // Private key export
	RespCodeDisabled          = 15 // Feature disabled
	RespCodeContactMsgRecvV3  = 16 // Contact message received (ver >= 3)
	RespCodeChannelMsgRecvV3  = 17 // Channel message received (ver >= 3)
	RespCodeChannelInfo       = 18 // Channel information
	RespCodeSignStart         = 19 // Signing started
	RespCodeSignature         = 20 // Signature data
	RespCodeCustomVars        = 21 // Custom variables
	RespCodeAdvertPath        = 22 // Advertisement path
	RespCodeTuningParams      = 23 // Tuning parameters
	RespCodeStats             = 24 // Statistics (v8+)
	RespCodeAutoaddConfig     = 25 // Auto-add configuration
	RespAllowedRepeatFreq     = 26 // Allowed repeat frequencies
	RespCodeChannelDataRecv   = 27 // Channel data received (v1.15.0+)
	RespCodeDefaultFloodScope = 28 // Default flood scope info (v1.15.0+)
)

// Push codes sent asynchronously from radio to host.
const (
	PushCodeMsgWaiting = 0x01 // Message waiting notification
)

// Statistics sub-types for CmdGetStats.
const (
	StatsTypeCore    = 0 // Core mesh statistics
	StatsTypeRadio   = 1 // Radio statistics
	StatsTypePackets = 2 // Packet statistics
)

// Error codes carried in a RespCodeErr frame ([RespCodeErr][code]). Values match
// the firmware ERR_CODE_* macros (companion_radio/MyMesh.cpp), which is what the
// host apps decode; do not renumber them.
const (
	ErrCodeUnsupportedCmd = 1
	ErrCodeNotFound       = 2
	ErrCodeTableFull      = 3
	ErrCodeBadState       = 4
	ErrCodeFileIOError    = 5
	ErrCodeIllegalArg     = 6
)

// Path hash modes for CmdSetPathHashMode.
const (
	PathHashMode1Byte = 0 // 1-byte path hashes
	PathHashMode2Byte = 1 // 2-byte path hashes
	PathHashMode3Byte = 2 // 3-byte path hashes
)

// Special path length values.
const (
	PathLenUnknown = 0xFF // Unknown path (use flood routing)
)

// Frame-size constants (MaxFrameSize, MaxChannelDataLength, FrameHeaderSize)
// live in constants.go.
