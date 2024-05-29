package notifications

import (
	"context"
	"sync/atomic"
	"time"

	"cdr.dev/slog"
	"github.com/coder/coder/v2/coderd/notifications/renderer"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/notifications/dispatcher"
)

const (
	// TODO: configurable?
	NotifierQueueSize     = 10
	NotifierLeaseLength   = time.Minute * 10
	NotifierFetchInterval = time.Second * 15
)

type notifier struct {
	id    uuid.UUID
	ctx   context.Context
	log   slog.Logger
	store Store

	tick           *time.Ticker
	stopped        atomic.Bool
	quit           chan any
	dispatcherSMTP dispatcher.SMTPDispatcher
	rendererText   renderer.TextRenderer
	rendererHTML   renderer.HTMLRenderer
}

func newNotifier(ctx context.Context, log slog.Logger, db Store) *notifier {
	id := uuid.New()
	return &notifier{
		id:             id,
		ctx:            ctx,
		log:            log.With(slog.F("notifier", id)),
		quit:           make(chan any),
		tick:           time.NewTicker(NotifierFetchInterval),
		store:          db,
		dispatcherSMTP: dispatcher.SMTPDispatcher{},
		rendererHTML:   renderer.HTMLRenderer{},
	}
}

func (n *notifier) run(ctx context.Context, success chan<- dispatchResult, failure chan<- dispatchResult) error {
	defer n.tick.Stop()

	// TODO: idea from Cian: instead of querying the database on a short interval, we could wait for pubsub notifications.
	//		 if 100 notifications are enqueued, we shouldn't activate this routine for each one; so how to debounce these?
	//		 PLUS we should also have an interval (but a longer one, maybe 1m) to account for retries (those will not get
	//		 triggered by a code path, but rather by a timeout expiring which makes the message retryable)
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
	n.log.Debug(ctx, "attempting to dequeue messages")

	msgs, err := n.fetch(ctx)
	if err != nil {
		return xerrors.Errorf("fetch messages: %w", err)
	}

	dispatches, dCtx := errgroup.WithContext(ctx)
	dCtx, cancel := context.WithCancel(dCtx)
	defer cancel()

	for _, msg := range msgs {
		dispatches.Go(func() error {
			// Dispatch must only return an error for exceptional cases, NOT for failed messages.
			// The first message to return an error cancels the errgroup's context.
			return n.dispatch(ctx, msg, success, failure)
		})
	}

	select {
	case <-ctx.Done():
		n.log.Warn(context.Background(), "context canceled")
		return ctx.Err()
	case <-n.quit:
		n.log.Warn(ctx, "gracefully stopped")
		return nil
	// Wait for all dispatches to complete or for a timeout, whichever comes first.
	case <-dCtx.Done():
		if dCtx.Err() != nil {
			n.log.Error(ctx, "dispatch failed", slog.Error(dCtx.Err()))
		}
		return nil
	default:
	}

	n.log.Debug(ctx, "dispatch completed", slog.F("count", len(msgs)))
	return nil
}

func (n *notifier) fetch(ctx context.Context) ([]database.AcquireNotificationMessagesRow, error) {
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

func (n *notifier) dispatch(ctx context.Context, msg database.AcquireNotificationMessagesRow, success, failure chan<- dispatchResult) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*10) // TODO: configurable
	defer cancel()

	var err error
	switch msg.Receiver {
	case database.NotificationReceiverSmtp:
		var title, body string
		if title, err = n.rendererText.Render(msg.TitleTemplate, msg.Input); err != nil {
			break
		}
		if body, err = n.rendererHTML.Render(msg.BodyTemplate, msg.Input); err != nil {
			break
		}
		err = n.dispatcherSMTP.Send(ctx, msg.Input, title, body)
	default:
		err = xerrors.Errorf("unrecognised receiver: %s", msg.Receiver)
	}

	// Don't try to accumulate message responses if the context has been canceled.
	// This message's lease will expire in the store and will be requeued.
	// It's possible this will lead to a message being delivered more than once, and that is why we should
	// generally be calling Stop() instead of canceling the context.
	if xerrors.Is(err, context.Canceled) {
		return err
	}

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
