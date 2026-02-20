package advert

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kabili207/meshcore-go/device/router"
)

const (
	// DefaultLocalAdvertInterval is the default local (zero-hop) advert interval
	// in firmware units. Actual interval = value * 2 minutes.
	DefaultLocalAdvertInterval = 1 // 2 minutes

	// DefaultFloodAdvertInterval is the default flood advert interval in hours.
	DefaultFloodAdvertInterval = 12 // 12 hours

	// tickInterval is the resolution of the scheduler's timer check loop.
	tickInterval = time.Second
)

// SchedulerConfig configures the ADVERT scheduler.
type SchedulerConfig struct {
	// LocalAdvertInterval is the interval for zero-hop (local) advertisements.
	// Actual interval = value * 2 minutes. Set to 0 to disable local adverts.
	// Default: 1 (= 2 minutes).
	LocalAdvertInterval uint8

	// FloodAdvertInterval is the interval for flood advertisements in hours.
	// Set to 0 to disable flood adverts.
	// Default: 12 (= 12 hours).
	FloodAdvertInterval uint8

	// Logger for scheduler events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Scheduler periodically broadcasts self-advertisements over the mesh.
// It manages two independent timers: one for local (zero-hop) adverts and
// one for flood adverts. A flood advert also resets the local timer.
//
// This corresponds to the firmware's MyMesh advertisement timer logic.
type Scheduler struct {
	cfg    SchedulerConfig
	log    *slog.Logger
	router *router.Router
	build  AdvertBuilder

	mu              sync.Mutex
	nextLocalAdvert time.Time
	nextFloodAdvert time.Time
	cancel          context.CancelFunc

	// nowFn allows overriding time.Now() for testing.
	nowFn func() time.Time
}

// NewScheduler creates an ADVERT scheduler.
//
// Parameters:
//   - r: the router to send advertisements through
//   - build: a function that creates a fresh ADVERT packet (see NewSelfAdvertBuilder)
//   - cfg: scheduler configuration
func NewScheduler(r *router.Router, build AdvertBuilder, cfg SchedulerConfig) *Scheduler {
	if cfg.LocalAdvertInterval == 0 && cfg.FloodAdvertInterval == 0 {
		// Both intervals zero means use defaults
		cfg.LocalAdvertInterval = DefaultLocalAdvertInterval
		cfg.FloodAdvertInterval = DefaultFloodAdvertInterval
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		cfg:    cfg,
		log:    logger.WithGroup("advert"),
		router: r,
		build:  build,
		nowFn:  time.Now,
	}
}

// Start begins the periodic advertisement loop. It blocks until the context
// is cancelled. Typically called in a goroutine:
//
//	go scheduler.Start(ctx)
func (s *Scheduler) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()

	s.resetTimers()

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkTimers()
		}
	}
}

// Stop cancels the scheduler's context, stopping the advertisement loop.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
}

// SendNow triggers an immediate advertisement. If flood is true, sends a
// flood advert and resets both timers. Otherwise sends a local (zero-hop)
// advert and resets only the local timer.
func (s *Scheduler) SendNow(flood bool) {
	pkt := s.build()
	if pkt == nil {
		s.log.Warn("failed to build advert for immediate send")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if flood {
		s.router.SendFlood(pkt)
		s.log.Debug("sent immediate flood advert")
		s.resetFloodTimerLocked()
		s.resetLocalTimerLocked()
	} else {
		s.router.SendZeroHop(pkt)
		s.log.Debug("sent immediate local advert")
		s.resetLocalTimerLocked()
	}
}

// UpdateIntervals updates the scheduling intervals at runtime.
// Setting an interval to 0 disables that timer type.
func (s *Scheduler) UpdateIntervals(localInterval, floodInterval uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cfg.LocalAdvertInterval = localInterval
	s.cfg.FloodAdvertInterval = floodInterval

	// Recalculate next fire times based on new intervals
	now := s.nowFn()
	if localInterval > 0 {
		s.nextLocalAdvert = now.Add(localAdvertDuration(localInterval))
	} else {
		s.nextLocalAdvert = time.Time{}
	}
	if floodInterval > 0 {
		s.nextFloodAdvert = now.Add(floodAdvertDuration(floodInterval))
	} else {
		s.nextFloodAdvert = time.Time{}
	}
}

// checkTimers checks if either timer has elapsed and sends the appropriate advert.
// Matches the firmware's loop logic: flood check first, then local.
func (s *Scheduler) checkTimers() {
	s.mu.Lock()
	now := s.nowFn()

	// Flood advert check (higher priority — also resets local timer)
	if !s.nextFloodAdvert.IsZero() && !now.Before(s.nextFloodAdvert) {
		s.mu.Unlock()

		pkt := s.build()
		if pkt != nil {
			s.router.SendFlood(pkt)
			s.log.Debug("sent scheduled flood advert")
		}

		s.mu.Lock()
		s.resetFloodTimerLocked()
		s.resetLocalTimerLocked()
		s.mu.Unlock()
		return
	}

	// Local advert check
	if !s.nextLocalAdvert.IsZero() && !now.Before(s.nextLocalAdvert) {
		s.mu.Unlock()

		pkt := s.build()
		if pkt != nil {
			s.router.SendZeroHop(pkt)
			s.log.Debug("sent scheduled local advert")
		}

		s.mu.Lock()
		s.resetLocalTimerLocked()
		s.mu.Unlock()
		return
	}

	s.mu.Unlock()
}

// resetTimers initializes both timer deadlines based on current config.
func (s *Scheduler) resetTimers() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetLocalTimerLocked()
	s.resetFloodTimerLocked()
}

// resetLocalTimerLocked sets the next local advert time. Must be called with s.mu held.
func (s *Scheduler) resetLocalTimerLocked() {
	if s.cfg.LocalAdvertInterval > 0 {
		s.nextLocalAdvert = s.nowFn().Add(localAdvertDuration(s.cfg.LocalAdvertInterval))
	} else {
		s.nextLocalAdvert = time.Time{}
	}
}

// resetFloodTimerLocked sets the next flood advert time. Must be called with s.mu held.
func (s *Scheduler) resetFloodTimerLocked() {
	if s.cfg.FloodAdvertInterval > 0 {
		s.nextFloodAdvert = s.nowFn().Add(floodAdvertDuration(s.cfg.FloodAdvertInterval))
	} else {
		s.nextFloodAdvert = time.Time{}
	}
}

// localAdvertDuration calculates the actual local advert interval.
// Firmware formula: interval * 2 * 60 * 1000 ms = interval * 2 minutes.
func localAdvertDuration(interval uint8) time.Duration {
	return time.Duration(interval) * 2 * time.Minute
}

// floodAdvertDuration calculates the actual flood advert interval.
// Firmware formula: interval * 60 * 60 * 1000 ms = interval hours.
func floodAdvertDuration(interval uint8) time.Duration {
	return time.Duration(interval) * time.Hour
}
