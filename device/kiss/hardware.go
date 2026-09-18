package kiss

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"

	cayennelpp "github.com/TheThingsNetwork/go-cayenne-lib"
	kisscodec "github.com/kabili207/meshcore-go/core/codec/kiss"
	"github.com/kabili207/meshcore-go/core/crypto"
)

// handleHardware dispatches a SetHardware sub-command.
func (c *conn) handleHardware(ctx context.Context, subCmd uint8, data []byte) {
	switch subCmd {
	case kisscodec.HWCmdGetIdentity:
		c.handleGetIdentity()
	case kisscodec.HWCmdGetRandom:
		c.handleGetRandom(data)
	case kisscodec.HWCmdVerifySignature:
		c.handleVerifySignature(data)
	case kisscodec.HWCmdSignData:
		c.handleSignData(data)
	case kisscodec.HWCmdEncryptData:
		c.handleEncryptData(data)
	case kisscodec.HWCmdDecryptData:
		c.handleDecryptData(data)
	case kisscodec.HWCmdKeyExchange:
		c.handleKeyExchange(data)
	case kisscodec.HWCmdHash:
		c.handleHash(data)
	case kisscodec.HWCmdSetRadio:
		c.handleSetRadio(data)
	case kisscodec.HWCmdSetTxPower:
		c.handleSetTxPower(data)
	case kisscodec.HWCmdGetRadio:
		c.sendHardware(kisscodec.HWRespRadio, c.m.RadioConfig().Encode())
	case kisscodec.HWCmdGetTxPower:
		c.sendHardware(kisscodec.HWRespTxPower, []byte{c.m.TxPower()})
	case kisscodec.HWCmdGetCurrentRssi:
		c.handleGetCurrentRSSI()
	case kisscodec.HWCmdIsChannelBusy:
		c.handleIsChannelBusy()
	case kisscodec.HWCmdGetAirtime:
		c.handleGetAirtime(data)
	case kisscodec.HWCmdGetNoiseFloor:
		c.handleGetNoiseFloor()
	case kisscodec.HWCmdGetVersion:
		c.sendHardware(kisscodec.HWRespVersion, []byte{kisscodec.FirmwareVersion, 0})
	case kisscodec.HWCmdGetStats:
		c.handleGetStats()
	case kisscodec.HWCmdGetBattery:
		c.handleGetBattery()
	case kisscodec.HWCmdGetMCUTemp:
		c.handleGetMCUTemp()
	case kisscodec.HWCmdGetSensors:
		c.handleGetSensors(data)
	case kisscodec.HWCmdGetDeviceName:
		c.sendHardware(kisscodec.HWRespDeviceName, []byte(c.m.cfg.DeviceName))
	case kisscodec.HWCmdPing:
		c.sendHardware(kisscodec.HWRespPong, nil)
	case kisscodec.HWCmdReboot:
		c.handleReboot()
	case kisscodec.HWCmdSetSignalReport:
		c.handleSetSignalReport(data)
	case kisscodec.HWCmdGetSignalReport:
		c.sendSignalReportState()
	default:
		c.sendError(kisscodec.HWErrUnknownCmd)
	}
}

// identity returns the configured key pair, answering NoCallback and reporting
// false when the modem was given no identity to act as.
func (c *conn) identity() (*crypto.KeyPair, bool) {
	kp := c.m.cfg.Identity
	if kp == nil {
		c.sendError(kisscodec.HWErrNoCallback)
		return nil, false
	}
	return kp, true
}

func (c *conn) handleGetIdentity() {
	kp, ok := c.identity()
	if !ok {
		return
	}
	c.sendHardware(kisscodec.HWRespIdentity, kp.PublicKey)
}

func (c *conn) handleGetRandom(data []byte) {
	if len(data) < 1 {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}
	n := data[0]
	if n < 1 || n > kisscodec.MaxRandomSize {
		c.sendError(kisscodec.HWErrInvalidParam)
		return
	}

	buf := make([]byte, n)
	if _, err := c.m.cfg.Rand.Read(buf); err != nil {
		c.m.log.Debug("random source failed", "error", err)
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}
	c.sendHardware(kisscodec.HWRespRandom, buf)
}

func (c *conn) handleVerifySignature(data []byte) {
	pubKey, signature, message, err := kisscodec.ParseVerifyRequest(data)
	if err != nil {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}

	var result byte
	if ed25519.Verify(ed25519.PublicKey(pubKey), message, signature) {
		result = 0x01
	}
	c.sendHardware(kisscodec.HWRespVerify, []byte{result})
}

func (c *conn) handleSignData(data []byte) {
	if len(data) < 1 {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}
	kp, ok := c.identity()
	if !ok {
		return
	}
	c.sendHardware(kisscodec.HWRespSignature, ed25519.Sign(kp.PrivateKey, data))
}

func (c *conn) handleEncryptData(data []byte) {
	secret, plaintext, err := kisscodec.ParseEncryptRequest(data)
	if err != nil {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}

	sealed, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		c.m.log.Debug("encrypt failed", "error", err)
		c.sendError(kisscodec.HWErrEncryptFailed)
		return
	}
	c.sendHardware(kisscodec.HWRespEncrypted, sealed)
}

func (c *conn) handleDecryptData(data []byte) {
	secret, sealed, err := kisscodec.ParseDecryptRequest(data)
	if err != nil {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}

	plaintext, err := crypto.DecryptAddressedWithSecret(sealed, secret)
	if err != nil {
		c.sendError(kisscodec.HWErrMacFailed)
		return
	}
	c.sendHardware(kisscodec.HWRespDecrypted, plaintext)
}

func (c *conn) handleKeyExchange(data []byte) {
	if len(data) < kisscodec.PubKeySize {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}
	kp, ok := c.identity()
	if !ok {
		return
	}

	secret, err := crypto.ComputeSharedSecret(kp.PrivateKey, data[:kisscodec.PubKeySize])
	if err != nil {
		c.m.log.Debug("key exchange failed", "error", err)
		c.sendError(kisscodec.HWErrInvalidParam)
		return
	}
	c.sendHardware(kisscodec.HWRespSharedSecret, secret)
}

func (c *conn) handleHash(data []byte) {
	if len(data) < 1 {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}
	sum := sha256.Sum256(data)
	c.sendHardware(kisscodec.HWRespHash, sum[:])
}

func (c *conn) handleSetRadio(data []byte) {
	cfg, err := kisscodec.DecodeRadioConfig(data)
	if err != nil {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}
	if c.m.cfg.SetRadio == nil {
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}
	if err := c.m.cfg.SetRadio(cfg); err != nil {
		c.m.log.Debug("set radio failed", "error", err)
		c.sendError(kisscodec.HWErrInvalidParam)
		return
	}

	c.m.mu.Lock()
	c.m.radioCfg = cfg
	c.m.mu.Unlock()

	c.sendHardware(kisscodec.HWRespOK, nil)
}

func (c *conn) handleSetTxPower(data []byte) {
	if len(data) < 1 {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}
	if c.m.cfg.SetTxPower == nil {
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}
	if err := c.m.cfg.SetTxPower(data[0]); err != nil {
		c.m.log.Debug("set tx power failed", "error", err)
		c.sendError(kisscodec.HWErrInvalidParam)
		return
	}

	c.m.mu.Lock()
	c.m.txPower = data[0]
	c.m.mu.Unlock()

	c.sendHardware(kisscodec.HWRespOK, nil)
}

func (c *conn) handleGetCurrentRSSI() {
	if c.m.cfg.CurrentRSSI == nil {
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}
	c.sendHardware(kisscodec.HWRespCurrentRssi, []byte{byte(c.m.cfg.CurrentRSSI())})
}

// handleIsChannelBusy reports a clear channel when no sensor is configured,
// which is the same assumption the CSMA state machine makes.
func (c *conn) handleIsChannelBusy() {
	var busy byte
	if c.channelBusy() {
		busy = 0x01
	}
	c.sendHardware(kisscodec.HWRespChannelBusy, []byte{busy})
}

func (c *conn) handleGetAirtime(data []byte) {
	if len(data) < 1 {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}
	if c.m.cfg.EstimateAirtime == nil {
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}

	ms := c.m.cfg.EstimateAirtime(int(data[0])).Milliseconds()
	if ms < 0 {
		ms = 0
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(ms))
	c.sendHardware(kisscodec.HWRespAirtime, buf)
}

func (c *conn) handleGetNoiseFloor() {
	if c.m.cfg.NoiseFloor == nil {
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(c.m.cfg.NoiseFloor()))
	c.sendHardware(kisscodec.HWRespNoiseFloor, buf)
}

func (c *conn) handleGetStats() {
	if c.m.cfg.Stats == nil {
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}
	c.sendHardware(kisscodec.HWRespStats, c.m.cfg.Stats().Encode())
}

func (c *conn) handleGetBattery() {
	if c.m.cfg.Battery == nil {
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, c.m.cfg.Battery())
	c.sendHardware(kisscodec.HWRespBattery, buf)
}

func (c *conn) handleGetMCUTemp() {
	if c.m.cfg.MCUTemp == nil {
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}
	temp, ok := c.m.cfg.MCUTemp()
	if !ok {
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(int16(temp*10)))
	c.sendHardware(kisscodec.HWRespMCUTemp, buf)
}

// handleGetSensors answers with a CayenneLPP payload, or an empty one when
// there is nothing to report. The permission byte is passed through to the
// provider unchanged.
func (c *conn) handleGetSensors(data []byte) {
	if len(data) < 1 {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}
	if c.m.cfg.Telemetry == nil {
		c.sendHardware(kisscodec.HWRespSensors, nil)
		return
	}

	enc := cayennelpp.NewEncoder()
	c.m.cfg.Telemetry.QuerySensors(data[0], enc)
	c.sendHardware(kisscodec.HWRespSensors, enc.Bytes())
}

// handleReboot acknowledges first so the host sees the reply before the modem
// goes away, then runs the hook and drops the connection.
func (c *conn) handleReboot() {
	if c.m.cfg.OnReboot == nil {
		c.sendError(kisscodec.HWErrNoCallback)
		return
	}
	c.sendHardware(kisscodec.HWRespOK, nil)

	go func() {
		c.m.cfg.OnReboot()
		c.cancel()
	}()
}

func (c *conn) handleSetSignalReport(data []byte) {
	if len(data) < 1 {
		c.sendError(kisscodec.HWErrInvalidLength)
		return
	}
	c.mu.Lock()
	c.signalReport = data[0] != 0
	c.mu.Unlock()
	c.sendSignalReportState()
}

func (c *conn) sendSignalReportState() {
	var v byte
	if c.signalReportEnabled() {
		v = 0x01
	}
	c.sendHardware(kisscodec.HWRespSignalReport, []byte{v})
}
