package notifications

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd/database"
)

const MaxAttempts = 5 // TODO: configurable

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
	db        Store
	mu        sync.Mutex
	notifiers []*notifier

	stop           chan any
	notifierCtx    context.Context
	notifierCancel context.CancelCauseFunc
}

type Store interface {
	AcquireNotificationMessages(ctx context.Context, params database.AcquireNotificationMessagesParams) ([]database.NotificationMessage, error)
}

func NewManager(db Store) *Manager {
	return &Manager{db: db, stop: make(chan any)}
}

func (m *Manager) Run(ctx context.Context, nc int) error {
	select {
	case <-m.stop:
		return xerrors.Errorf("gracefully stopped")
	case <-ctx.Done():
		return xerrors.Errorf("ungraceful stop: %w", ctx.Err())
	default:
	}

	var eg errgroup.Group

	var (
		success = make(chan dispatchResult, 50)
		failure = make(chan dispatchResult, 50)
	)

	for i := 0; i < nc; i++ {
		eg.Go(func() error {
			m.mu.Lock()
			n := newNotifier(ctx, m.db)
			m.notifiers = append(m.notifiers, n)
			m.mu.Unlock()
			return n.run(ctx, success, failure)
		})
	}

	go func() {
		// Every second, collect the messages in the channels and bulk update them in the database.
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				fmt.Printf("context canceled with %d success and %d failure messages still pending!\n", len(success), len(failure))
				return
			case <-m.stop:
				// Drain before stopping.
				m.drain(success, failure)
				return
			case <-tick.C:
				m.drain(success, failure)
			}
		}
	}()

	err := eg.Wait()
	fmt.Printf("MANAGER DONE: %v\n", err)
	return err
}

func (m *Manager) drain(success, failure <-chan dispatchResult) {
	var wg sync.WaitGroup
	wg.Add(2)

	var sCount, fCount int

	go func() {
		defer wg.Done()
		count := len(success)
		for i := 0; i < count; i++ {
			_ = <-success
			// fmt.Printf("[%s] SUCCESS: %s\n", res.notifier, res.msg)
			sCount++
		}
	}()

	go func() {
		defer wg.Done()
		count := len(failure)
		for i := 0; i < count; i++ {
			_ = <-failure
			// fmt.Printf("[%s] FAILURE: %s -> %s (%v)\n", res.notifier, res.msg, res.err, res.retryable)
			fCount++
		}
	}()

	wg.Wait()

	fmt.Printf("\t>S: %d, F: %d, T: %d\n", sCount, fCount, sCount+fCount)
}

func (m *Manager) Stop() {
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
