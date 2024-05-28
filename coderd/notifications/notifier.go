package notifications

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/notifications/dispatcher"
)

const (
	NotifierQueueSize   = 10
	NotifierLeaseLength = time.Minute * 10
)

type notifier struct {
	id            uuid.UUID
	q             []database.NotificationMessage
	store         Store
	ctx           context.Context
	dispatchCount atomic.Int32

	tick    *time.Ticker
	stopped atomic.Bool
	quit    chan any
	smtp    dispatcher.SMTPDispatcher
}

func newNotifier(ctx context.Context, db Store) *notifier {
	return &notifier{
		id:    uuid.New(),
		ctx:   ctx,
		q:     make([]database.NotificationMessage, NotifierQueueSize),
		quit:  make(chan any),
		tick:  time.NewTicker(time.Second * 15),
		store: db,
		smtp:  dispatcher.SMTPDispatcher{},
	}
}

func (n *notifier) run(ctx context.Context, success chan<- dispatchResult, failure chan<- dispatchResult) error {
	defer n.tick.Stop()

	for {
		err := n.process(ctx, success, failure)
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return xerrors.Errorf("[%s] %w", n.id, ctx.Err())
		case <-n.quit:
			return xerrors.Errorf("[%s] stopped!", n.id)
		case <-n.tick.C:
			// sleep until next invocation
		}
	}
}

func (n *notifier) process(ctx context.Context, success chan<- dispatchResult, failure chan<- dispatchResult) error {
	fmt.Printf("[%s] TICK!\n", n.id)

	msgs, err := n.fetch(ctx)
	if err != nil {
		return xerrors.Errorf("fetch messages: %w", err)
	}

	eg, egCtx := errgroup.WithContext(ctx)
	egCtx, cancel := context.WithCancel(egCtx)
	for _, msg := range msgs {
		eg.Go(func() error {
			x := n.dispatch(ctx, msg, success, failure)
			fmt.Printf("[%s] [%s] %v\n", n.id, msg.ID, x)
			return x
		})
	}

	select {
	// Bail out if context canceled or notifier is stopped.
	case <-ctx.Done():
		fmt.Printf("canceled! %s\n", ctx.Err())
		cancel()
		return ctx.Err()
	case <-n.quit:
		fmt.Printf("stopped!\n")
		cancel()
		return xerrors.New("stopped")

	// Wait for all dispatches to complete or for a timeout, whichever comes first.
	case <-egCtx.Done():
		fmt.Printf("dispatch ended: %s\n", egCtx.Err())
		cancel()
	// TODO: chaos monkey, remove
	case <-time.After(time.Millisecond * 450):
		fmt.Printf("timeout!\n")
		cancel()
	}

	fmt.Printf("[%s]>>>>GOT TO END\n", n.id)
	return nil
}

func (n *notifier) fetch(ctx context.Context) ([]database.NotificationMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, NotifierLeaseLength)
	deadline, _ := ctx.Deadline()
	defer cancel()

	msgs, err := n.store.AcquireNotificationMessages(ctx, database.AcquireNotificationMessagesParams{
		Count:       NotifierQueueSize,
		NotifierID:  n.id,
		LeasedUntil: deadline,
		UserID:      uuid.New(), // TODO: use real user ID
		OrgID:       uuid.New(), // TODO: use real org ID
	})
	if err != nil {
		return nil, xerrors.Errorf("acquire messages: %w", err)
	}

	return msgs, nil
}

func (n *notifier) dispatch(ctx context.Context, msg database.NotificationMessage, success, failure chan<- dispatchResult) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*10) // TODO: configurable
	defer cancel()

	err := n.smtp.Send(ctx, msg, "my title", "my body")

	// Don't try to accumulate message responses if the context has been canceled.
	// This message's lease will expire in the store and will be requeued.
	// It's possible this will lead to a message being delivered more than once, and that is why we should
	// generally be calling Stop() instead of canceling the context.
	if xerrors.Is(err, context.Canceled) {
		return err
	}

	n.dispatchCount.Add(1)

	if err != nil {
		retryable := msg.AttemptCount.Int32+1 < MaxAttempts
		failure <- dispatchResult{notifier: n.id, msg: msg.ID, err: err, retryable: retryable}
	} else {
		success <- dispatchResult{notifier: n.id, msg: msg.ID}
	}

	return nil
}

func (n *notifier) stop() {
	if n.stopped.Load() {
		return
	}
	n.stopped.Store(true)
	n.tick.Stop()
	close(n.quit)
}
