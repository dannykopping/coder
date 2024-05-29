package notifications

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"cdr.dev/slog"

	"github.com/coder/coder/v2/coderd/database"
)

const (
	MaxAttempts          = 5           // TODO: configurable
	BulkUpdateBufferSize = 50          // TODO: configurable
	BulkUpdateInterval   = time.Second // TODO: configurable
)

// Manager manages all notifications being enqueued and dispatched.
//
// Manager maintains a group of notifiers: these consume the queue of notification messages in the store.
//
// Notifiers dequeue messages from the store _n_ at a time and concurrently "dispatch" these messages, meaning they are
// sent to their respective receivers (email, webhook, etc).
//
// To reduce load on the store, successful and failed dispatches are accumulated in two separate buffers (success/failure)
// in the Manager, and updates are sent to the store about which messages succeeded or failed every _n_ seconds.
// These buffers are limited in size, naturally introduces some backpressure; if there are hundreds of messages to be
// sent but they start failing too quickly, the buffers (receive channels) will fill up and block senders, which will
// slow down the dispatch rate.
//
// NOTE: The above backpressure mechanism only works if all notifiers live within the same process, which may not be true
// forever, such as if we split notifiers out into separate targets for greater processing throughput; in this case we
// will need an alternative mechanism for handling backpressure.
type Manager struct {
	mu  sync.Mutex
	log slog.Logger

	store     Store
	notifiers []*notifier

	stop    chan any
	stopped atomic.Bool
}

type Store interface {
	AcquireNotificationMessages(ctx context.Context, params database.AcquireNotificationMessagesParams) ([]database.AcquireNotificationMessagesRow, error)
}

func NewManager(store Store, log slog.Logger) *Manager {
	return &Manager{store: store, stop: make(chan any), log: log}
}

func (m *Manager) Run(ctx context.Context, nc int) error {
	select {
	case <-m.stop:
		m.log.Warn(ctx, "gracefully stopped")
		return xerrors.Errorf("gracefully stopped")
	case <-ctx.Done():
		m.log.Error(ctx, "ungracefully stopped", slog.Error(ctx.Err()))
		return xerrors.Errorf("notifications: %w", ctx.Err())
	default:
	}

	var eg errgroup.Group

	var (
		success = make(chan dispatchResult, BulkUpdateBufferSize)
		failure = make(chan dispatchResult, BulkUpdateBufferSize)
	)

	for i := 0; i < nc; i++ {
		eg.Go(func() error {
			m.mu.Lock()
			n := newNotifier(ctx, m.log, m.store)
			m.notifiers = append(m.notifiers, n)
			m.mu.Unlock()
			return n.run(ctx, success, failure)
		})
	}

	go func() {
		// Every interval, collect the messages in the channels and bulk update them in the database.
		tick := time.NewTicker(BulkUpdateInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				// Nothing we can do in this scenario except bail out; after the message lease expires, the messages will
				// be requeued and users will receive duplicates.
				// This is an explicit trade-off between keeping the database load light (by bulk-updating records) and
				// exactly-once delivery.
				//
				// The current assumption is that duplicate delivery of these messages is, at worst, slightly annoying.
				// If these notifications are triggering external actions (e.g. via webhooks) this could be more
				// consequential, and we may need a more sophisticated mechanism.
				//
				// TODO: mention the above tradeoff in documentation.
				if len(success)+len(failure) > 0 {
					m.log.Warn(ctx, "content canceled with pending updates in buffer, these messages will be sent again after lease expires",
						slog.F("success_count", len(success)), slog.F("failure_count", len(failure)))
				}
				return
			case <-m.stop:
				// Drain buffers before stopping.
				m.bulkUpdate(ctx, success, failure)
				return
			case <-tick.C:
				m.bulkUpdate(ctx, success, failure)
			}
		}
	}()

	err := eg.Wait()
	m.log.Info(ctx, "notification manager done")
	return err
}

// bulkUpdate updates messages in the store based on the given successful and failed message dispatch results.
func (m *Manager) bulkUpdate(ctx context.Context, success, failure <-chan dispatchResult) {
	// Nothing to do.
	if len(success)+len(failure) == 0 {
		return
	}

	m.log.Debug(ctx, "bulk update messages", slog.F("success_count", len(success)), slog.F("failure_count", len(failure)))

	var wg sync.WaitGroup
	wg.Add(2)

	var sCount, fCount int

	go func() {
		defer wg.Done()
		count := len(success)
		for i := 0; i < count; i++ {
			_ = <-success
			sCount++
		}
	}()

	go func() {
		defer wg.Done()
		count := len(failure)
		for i := 0; i < count; i++ {
			_ = <-failure
			fCount++
		}
	}()

	wg.Wait()
}

func (m *Manager) Stop() {
	if m.stopped.Load() {
		return
	}

	m.stopped.Store(true)
	for _, n := range m.notifiers {
		n.stop()
	}
	close(m.stop)
}

type dispatchResult struct {
	notifier  uuid.UUID
	msg       uuid.UUID
	err       error
	retryable bool
}
