package kiss

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	kisscodec "github.com/kabili207/meshcore-go/core/codec/kiss"
)

// ErrRequestTimeout is returned when the modem does not answer a SetHardware
// request within Config.RequestTimeout.
var ErrRequestTimeout = errors.New("kiss: timed out waiting for modem response")

// pendingRequest is the single outstanding SetHardware exchange. The protocol
// has no request identifiers, so only one may be in flight at a time.
type pendingRequest struct {
	want uint8
	ch   chan hwResult
}

type hwResult struct {
	data []byte
	err  error
}

// handleHardwareFrame routes an incoming SetHardware frame: the two unsolicited
// notifications are dispatched directly, and anything else answers the pending
// request.
func (t *Transport) handleHardwareFrame(subCmd uint8, data []byte) {
	switch subCmd {
	case kisscodec.HWRespTxDone:
		success := len(data) > 0 && data[0] != 0
		t.handleTxDone(success)
		return

	case kisscodec.HWRespRxMeta:
		meta, err := kisscodec.DecodeRxMeta(data)
		if err != nil {
			t.logger().Debug("malformed RxMeta from modem", "error", err)
			return
		}
		t.handleRxMeta(meta)
		return
	}

	t.mu.RLock()
	pending := t.pending
	t.mu.RUnlock()

	if subCmd == kisscodec.HWRespError {
		t.handleErrorFrame(pending, data)
		return
	}

	if pending == nil {
		t.logger().Debug("unsolicited SetHardware response ignored", "sub_command", subCmd)
		return
	}

	if subCmd != pending.want {
		t.logger().Debug("SetHardware response does not match pending request",
			"got", subCmd, "want", pending.want)
		return
	}

	out := make([]byte, len(data))
	copy(out, data)
	t.deliver(pending, hwResult{data: out})
}

// handleErrorFrame decides who an error belongs to. The protocol carries no
// correlation identifier, and a rejected data frame is reported as a bare
// error, so TxBusy goes to a waiting sender first: that is the only reading
// under which a refused transmission fails promptly instead of sitting out
// TxTimeout and then being credited with the next TxDone that arrives.
func (t *Transport) handleErrorFrame(pending *pendingRequest, data []byte) {
	code := uint8(kisscodec.HWErrUnknownCmd)
	if len(data) > 0 {
		code = data[0]
	}
	hwErr := &kisscodec.HardwareError{Code: code}

	if code == kisscodec.HWErrTxBusy && t.failPendingTx(hwErr) {
		return
	}
	if pending != nil {
		t.deliver(pending, hwResult{err: hwErr})
		return
	}
	t.logger().Warn("unsolicited modem error", "error", hwErr.Error())
}

// handleTxDone credits a transmission notification to the sender waiting for
// it, unless that sender already gave up. Each abandoned transmission still
// owes one notification, and delivering it to the next sender would report
// success for a packet that never went out.
func (t *Transport) handleTxDone(success bool) {
	t.mu.Lock()
	stale := t.staleTxDone > 0
	if stale {
		t.staleTxDone--
	} else if t.txDone != nil {
		select {
		case t.txDone <- txOutcome{success: success}:
		default:
		}
		t.txDone = nil
	}
	t.mu.Unlock()

	if stale {
		t.logger().Debug("dropping TxDone for an abandoned transmission", "success", success)
	}
	if t.cfg.OnTxDone != nil {
		t.cfg.OnTxDone(success)
	}
}

// deliver hands a result to the waiting request, if it is still waiting.
func (t *Transport) deliver(p *pendingRequest, res hwResult) {
	select {
	case p.ch <- res:
	default:
	}
}

// failPendingRequest releases a request blocked on a modem that went away.
func (t *Transport) failPendingRequest(cause error) {
	t.mu.RLock()
	pending := t.pending
	t.mu.RUnlock()

	if pending == nil {
		return
	}
	err := ErrNotConnected
	if cause != nil {
		err = fmt.Errorf("%w: %w", ErrNotConnected, cause)
	}
	t.deliver(pending, hwResult{err: err})
}

// request performs one SetHardware exchange. Requests are serialized because
// responses carry no correlation identifier.
//
// A caveat inherent to the protocol: the modem reports a rejected data frame as
// a bare error, so a TxBusy error arriving while a request is in flight will be
// attributed to that request.
func (t *Transport) request(ctx context.Context, subCmd uint8, data []byte, want uint8) ([]byte, error) {
	frame, err := kisscodec.EncodeHardwareFrame(subCmd, data)
	if err != nil {
		return nil, err
	}

	t.reqMu.Lock()
	defer t.reqMu.Unlock()

	pending := &pendingRequest{want: want, ch: make(chan hwResult, 1)}
	t.mu.Lock()
	t.pending = pending
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		t.pending = nil
		t.mu.Unlock()
	}()

	if err := t.writeFrame(frame); err != nil {
		return nil, err
	}

	timeout := t.cfg.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-pending.ch:
		return res.data, res.err
	case <-timer.C:
		return nil, ErrRequestTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// requireLen rejects a response too short for the fields it should carry. A
// modem running older firmware is the usual cause.
func requireLen(data []byte, n int, what string) error {
	if len(data) < n {
		return fmt.Errorf("kiss: %s response is %d bytes, want at least %d", what, len(data), n)
	}
	return nil
}

// Crypto offload. These run on the modem, using the identity it generated on
// first boot and stored in flash. A Go node with its own key has no reason to
// use them; they exist so a host can borrow the modem's identity.

// GetIdentity returns the modem's 32-byte Ed25519 public key.
func (t *Transport) GetIdentity(ctx context.Context) ([]byte, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetIdentity, nil, kisscodec.HWRespIdentity)
	if err != nil {
		return nil, err
	}
	if err := requireLen(data, kisscodec.PubKeySize, "identity"); err != nil {
		return nil, err
	}
	return data[:kisscodec.PubKeySize], nil
}

// GetRandom returns n bytes from the modem's hardware random number generator.
// n must be between 1 and 64.
func (t *Transport) GetRandom(ctx context.Context, n uint8) ([]byte, error) {
	if n < 1 || n > kisscodec.MaxRandomSize {
		return nil, fmt.Errorf("kiss: random length %d out of range 1-%d", n, kisscodec.MaxRandomSize)
	}
	data, err := t.request(ctx, kisscodec.HWCmdGetRandom, []byte{n}, kisscodec.HWRespRandom)
	if err != nil {
		return nil, err
	}
	if err := requireLen(data, int(n), "random"); err != nil {
		return nil, err
	}
	return data[:n], nil
}

// VerifySignature asks the modem to check an Ed25519 signature over message.
func (t *Transport) VerifySignature(ctx context.Context, pubKey, signature, message []byte) (bool, error) {
	payload, err := kisscodec.BuildVerifyRequest(pubKey, signature, message)
	if err != nil {
		return false, err
	}
	data, err := t.request(ctx, kisscodec.HWCmdVerifySignature, payload, kisscodec.HWRespVerify)
	if err != nil {
		return false, err
	}
	if err := requireLen(data, 1, "verify"); err != nil {
		return false, err
	}
	return data[0] != 0, nil
}

// SignData returns an Ed25519 signature over message, made with the modem's
// identity key.
func (t *Transport) SignData(ctx context.Context, message []byte) ([]byte, error) {
	data, err := t.request(ctx, kisscodec.HWCmdSignData, message, kisscodec.HWRespSignature)
	if err != nil {
		return nil, err
	}
	if err := requireLen(data, kisscodec.SignatureSize, "signature"); err != nil {
		return nil, err
	}
	return data[:kisscodec.SignatureSize], nil
}

// EncryptData encrypts plaintext under sharedSecret, returning the 2-byte MAC
// followed by the ciphertext. The ciphertext is zero-padded to a 16-byte
// multiple, so DecryptData returns padding the caller must trim.
func (t *Transport) EncryptData(ctx context.Context, sharedSecret, plaintext []byte) ([]byte, error) {
	payload, err := kisscodec.BuildEncryptRequest(sharedSecret, plaintext)
	if err != nil {
		return nil, err
	}
	return t.request(ctx, kisscodec.HWCmdEncryptData, payload, kisscodec.HWRespEncrypted)
}

// DecryptData verifies and decrypts a MAC-prefixed ciphertext produced by
// EncryptData. The result still carries the encryptor's zero padding.
func (t *Transport) DecryptData(ctx context.Context, sharedSecret, sealed []byte) ([]byte, error) {
	payload, err := kisscodec.BuildDecryptRequest(sharedSecret, sealed)
	if err != nil {
		return nil, err
	}
	return t.request(ctx, kisscodec.HWCmdDecryptData, payload, kisscodec.HWRespDecrypted)
}

// KeyExchange returns the X25519 shared secret between the modem's identity and
// remotePubKey.
func (t *Transport) KeyExchange(ctx context.Context, remotePubKey []byte) ([]byte, error) {
	if len(remotePubKey) != kisscodec.PubKeySize {
		return nil, fmt.Errorf("kiss: public key must be %d bytes, got %d", kisscodec.PubKeySize, len(remotePubKey))
	}
	data, err := t.request(ctx, kisscodec.HWCmdKeyExchange, remotePubKey, kisscodec.HWRespSharedSecret)
	if err != nil {
		return nil, err
	}
	if err := requireLen(data, kisscodec.PubKeySize, "shared secret"); err != nil {
		return nil, err
	}
	return data[:kisscodec.PubKeySize], nil
}

// Hash returns the SHA-256 digest of data, computed on the modem.
func (t *Transport) Hash(ctx context.Context, data []byte) ([]byte, error) {
	out, err := t.request(ctx, kisscodec.HWCmdHash, data, kisscodec.HWRespHash)
	if err != nil {
		return nil, err
	}
	if err := requireLen(out, kisscodec.HashSize, "hash"); err != nil {
		return nil, err
	}
	return out[:kisscodec.HashSize], nil
}

// Radio control and measurement.

// SetRadio reconfigures the LoRa modulation.
func (t *Transport) SetRadio(ctx context.Context, cfg RadioConfig) error {
	_, err := t.request(ctx, kisscodec.HWCmdSetRadio, cfg.Encode(), kisscodec.HWRespOK)
	return err
}

// GetRadio returns the modem's current LoRa modulation settings.
func (t *Transport) GetRadio(ctx context.Context) (RadioConfig, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetRadio, nil, kisscodec.HWRespRadio)
	if err != nil {
		return RadioConfig{}, err
	}
	return kisscodec.DecodeRadioConfig(data)
}

// SetTxPower sets the transmit power in dBm.
func (t *Transport) SetTxPower(ctx context.Context, dBm uint8) error {
	_, err := t.request(ctx, kisscodec.HWCmdSetTxPower, []byte{dBm}, kisscodec.HWRespOK)
	return err
}

// GetTxPower returns the transmit power in dBm.
func (t *Transport) GetTxPower(ctx context.Context) (uint8, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetTxPower, nil, kisscodec.HWRespTxPower)
	if err != nil {
		return 0, err
	}
	if err := requireLen(data, 1, "tx power"); err != nil {
		return 0, err
	}
	return data[0], nil
}

// GetCurrentRSSI returns an instantaneous channel RSSI reading in dBm.
func (t *Transport) GetCurrentRSSI(ctx context.Context) (int8, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetCurrentRssi, nil, kisscodec.HWRespCurrentRssi)
	if err != nil {
		return 0, err
	}
	if err := requireLen(data, 1, "rssi"); err != nil {
		return 0, err
	}
	return int8(data[0]), nil
}

// IsChannelBusy reports whether the radio is currently receiving.
func (t *Transport) IsChannelBusy(ctx context.Context) (bool, error) {
	data, err := t.request(ctx, kisscodec.HWCmdIsChannelBusy, nil, kisscodec.HWRespChannelBusy)
	if err != nil {
		return false, err
	}
	if err := requireLen(data, 1, "channel busy"); err != nil {
		return false, err
	}
	return data[0] != 0, nil
}

// GetAirtime returns the modem's estimate of how long a packet of the given
// length would occupy the channel.
func (t *Transport) GetAirtime(ctx context.Context, packetLen uint8) (time.Duration, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetAirtime, []byte{packetLen}, kisscodec.HWRespAirtime)
	if err != nil {
		return 0, err
	}
	if err := requireLen(data, 4, "airtime"); err != nil {
		return 0, err
	}
	return time.Duration(binary.LittleEndian.Uint32(data[:4])) * time.Millisecond, nil
}

// GetNoiseFloor returns the modem's calibrated noise floor in dBm. The modem
// recalibrates every couple of seconds.
func (t *Transport) GetNoiseFloor(ctx context.Context) (int16, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetNoiseFloor, nil, kisscodec.HWRespNoiseFloor)
	if err != nil {
		return 0, err
	}
	if err := requireLen(data, 2, "noise floor"); err != nil {
		return 0, err
	}
	return int16(binary.LittleEndian.Uint16(data[:2])), nil
}

// SetSignalReport enables or disables the RxMeta frames that follow each
// received packet, and returns the resulting state. Reporting is on by default.
func (t *Transport) SetSignalReport(ctx context.Context, enabled bool) (bool, error) {
	var v uint8
	if enabled {
		v = 1
	}
	data, err := t.request(ctx, kisscodec.HWCmdSetSignalReport, []byte{v}, kisscodec.HWRespSignalReport)
	if err != nil {
		return false, err
	}
	if err := requireLen(data, 1, "signal report"); err != nil {
		return false, err
	}
	return data[0] != 0, nil
}

// GetSignalReport reports whether the modem is sending RxMeta frames.
func (t *Transport) GetSignalReport(ctx context.Context) (bool, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetSignalReport, nil, kisscodec.HWRespSignalReport)
	if err != nil {
		return false, err
	}
	if err := requireLen(data, 1, "signal report"); err != nil {
		return false, err
	}
	return data[0] != 0, nil
}

// Device status.

// GetVersion returns the modem's KISS protocol version. This is not the mesh
// FIRMWARE_VER_CODE.
func (t *Transport) GetVersion(ctx context.Context) (uint8, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetVersion, nil, kisscodec.HWRespVersion)
	if err != nil {
		return 0, err
	}
	if err := requireLen(data, 1, "version"); err != nil {
		return 0, err
	}
	return data[0], nil
}

// GetStats returns the modem's lifetime packet counters.
func (t *Transport) GetStats(ctx context.Context) (Stats, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetStats, nil, kisscodec.HWRespStats)
	if err != nil {
		return Stats{}, err
	}
	return kisscodec.DecodeStats(data)
}

// GetBattery returns the battery voltage in millivolts.
func (t *Transport) GetBattery(ctx context.Context) (uint16, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetBattery, nil, kisscodec.HWRespBattery)
	if err != nil {
		return 0, err
	}
	if err := requireLen(data, 2, "battery"); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(data[:2]), nil
}

// GetMCUTemp returns the microcontroller temperature in degrees Celsius. Boards
// without a temperature sensor answer with a HardwareError carrying
// HWErrNoCallback.
func (t *Transport) GetMCUTemp(ctx context.Context) (float32, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetMCUTemp, nil, kisscodec.HWRespMCUTemp)
	if err != nil {
		return 0, err
	}
	if err := requireLen(data, 2, "mcu temperature"); err != nil {
		return 0, err
	}
	return float32(int16(binary.LittleEndian.Uint16(data[:2]))) / 10, nil
}

// GetSensors returns the modem's sensor readings as a CayenneLPP payload,
// filtered by the given permission mask (see the kiss codec's SensorPerm*
// constants). It returns nil when the modem has nothing to report.
func (t *Transport) GetSensors(ctx context.Context, permissions uint8) ([]byte, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetSensors, []byte{permissions}, kisscodec.HWRespSensors)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	return data, nil
}

// GetDeviceName returns the modem's board name.
func (t *Transport) GetDeviceName(ctx context.Context) (string, error) {
	data, err := t.request(ctx, kisscodec.HWCmdGetDeviceName, nil, kisscodec.HWRespDeviceName)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Ping checks that the modem is responding.
func (t *Transport) Ping(ctx context.Context) error {
	_, err := t.request(ctx, kisscodec.HWCmdPing, nil, kisscodec.HWRespPong)
	return err
}

// Reboot restarts the modem. It returns once the modem acknowledges; the
// connection drops immediately afterward, so the caller should Stop and
// reconnect.
func (t *Transport) Reboot(ctx context.Context) error {
	_, err := t.request(ctx, kisscodec.HWCmdReboot, nil, kisscodec.HWRespOK)
	return err
}
