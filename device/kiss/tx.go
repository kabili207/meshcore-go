package kiss

import (
	"context"
	"time"

	kisscodec "github.com/kabili207/meshcore-go/core/codec/kiss"
)

// kissTimeUnit is the resolution of the TXDELAY, SlotTime, and TXtail
// parameters: each counts 10ms steps.
const kissTimeUnit = 10 * time.Millisecond

// txTimeoutNumerator and txTimeoutDenominator give the firmware's 1.5x
// allowance over estimated airtime, used to bound how long CSMA waits out a
// busy channel.
const (
	txTimeoutNumerator   = 3
	txTimeoutDenominator = 2
)

// defaultBusyTimeout bounds the carrier-sense wait when Config.EstimateAirtime
// is not supplied and there is no airtime figure to scale.
const defaultBusyTimeout = 5 * time.Second

// handleData queues a host's packet for transmission. The host may have one
// packet outstanding, so a second arriving before the first completes is
// refused with TxBusy.
func (c *conn) handleData(ctx context.Context, data []byte) {
	c.mu.Lock()
	if c.txPending {
		c.mu.Unlock()
		c.sendError(kisscodec.HWErrTxBusy)
		return
	}
	if len(data) == 0 || len(data) > kisscodec.MaxPacketSize {
		// Firmware drops these without a reply.
		c.mu.Unlock()
		c.m.log.Debug("dropping host packet outside MTU", "len", len(data))
		return
	}
	c.txPending = true
	c.mu.Unlock()

	packet := make([]byte, len(data))
	copy(packet, data)

	go c.transmit(ctx, packet)
}

// transmit runs the CSMA state machine and hands the packet to the radio,
// reporting the outcome to the host as a TxDone notification.
func (c *conn) transmit(ctx context.Context, packet []byte) {
	defer func() {
		c.mu.Lock()
		c.txPending = false
		c.mu.Unlock()
	}()

	c.mu.Lock()
	fullDuplex := c.fullDuplex
	txDelay := c.txDelay
	txTail := c.txTail
	c.mu.Unlock()

	if !fullDuplex && !c.awaitChannel(ctx) {
		return
	}
	if !sleepCtx(ctx, time.Duration(txDelay)*kissTimeUnit) {
		return
	}

	// One packet on the air at a time, no matter how many hosts are connected.
	c.m.txMu.Lock()
	err := c.m.cfg.Radio.Send(ctx, packet)
	c.m.txMu.Unlock()

	if err != nil {
		c.m.log.Debug("radio transmit failed", "error", err)
	}

	// TXtail holds the channel after the transmission. It delays the
	// notification but not the release of the radio.
	if !sleepCtx(ctx, time.Duration(txTail)*kissTimeUnit) {
		return
	}

	result := byte(0x01)
	if err != nil {
		result = 0x00
	}
	c.sendHardware(kisscodec.HWRespTxDone, []byte{result})
}

// awaitChannel runs p-persistent CSMA: wait for a clear channel, then transmit
// with probability persistence/255, otherwise back off one slot and retry. It
// returns false if the context was cancelled.
//
// A channel that stays busy for longer than the time a maximum-length packet
// would take is treated as stuck, and the modem transmits anyway. That is the
// firmware's behavior, and the timeout restarts after every backoff slot.
func (c *conn) awaitChannel(ctx context.Context) bool {
	busyTimeout := c.busyTimeout()

	for {
		deadline := time.Now().Add(busyTimeout)

		for c.channelBusy() {
			if time.Now().After(deadline) {
				return true
			}
			if !sleepCtx(ctx, c.slotDuration()) {
				return false
			}
		}

		if c.drawPersistence() {
			return true
		}
		if !sleepCtx(ctx, c.slotDuration()) {
			return false
		}
	}
}

func (c *conn) slotDuration() time.Duration {
	c.mu.Lock()
	slot := c.slotTime
	c.mu.Unlock()
	if slot == 0 {
		// A zero slot would spin the carrier-sense loop with no delay.
		return kissTimeUnit
	}
	return time.Duration(slot) * kissTimeUnit
}

func (c *conn) busyTimeout() time.Duration {
	if c.m.cfg.EstimateAirtime == nil {
		return defaultBusyTimeout
	}
	est := c.m.cfg.EstimateAirtime(kisscodec.MaxPacketSize)
	if est <= 0 {
		return defaultBusyTimeout
	}
	return est * txTimeoutNumerator / txTimeoutDenominator
}

func (c *conn) channelBusy() bool {
	if c.m.cfg.IsChannelBusy == nil {
		return false
	}
	return c.m.cfg.IsChannelBusy()
}

// drawPersistence reports whether this slot wins the p-persistent draw. A
// random byte at or below the persistence parameter transmits, so 255 always
// transmits and 0 gives a one-in-256 chance.
func (c *conn) drawPersistence() bool {
	c.mu.Lock()
	p := c.persistence
	c.mu.Unlock()

	var b [1]byte
	if _, err := c.m.cfg.Rand.Read(b[:]); err != nil {
		// Without randomness, fall back to transmitting rather than stalling.
		c.m.log.Debug("CSMA random draw failed, transmitting", "error", err)
		return true
	}
	return b[0] <= p
}

// sleepCtx waits for d, reporting false if the context was cancelled first. A
// non-positive duration returns immediately.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
