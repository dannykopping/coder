package notifications

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/coder/v2/coderd/database"
	"github.com/google/uuid"
	"golang.org/x/xerrors"
)

const NotifierQueueSize = 10
const NotifierLeaseLength = time.Minute * 10

type notifier struct {
	id   uuid.UUID
	q    []database.NotificationMessage
	tick *time.Ticker

	close chan struct{}

	db Store
}

func newNotifier(db Store) *notifier {
	return &notifier{
		id:   uuid.New(),
		q:    make([]database.NotificationMessage, NotifierQueueSize),
		tick: time.NewTicker(time.Second * 5),

		close: make(chan struct{}, 1),

		db: db,
	}
}

func (n *notifier) run() error {
	for ; true; <-n.tick.C {
		fmt.Printf("[%s] TICK!\n", n.id)

		select {
		case <-n.close:
			n.tick.Stop()
			return xerrors.Errorf("%s closed", n.id)
		default:
		}

		msgs, err := n.fetch(context.Background())
		if err != nil {
			return xerrors.Errorf("fetch messages: %w", err)
		}

		type dispatchResult struct {
			id  uuid.UUID
			err error
		}

		var closed atomic.Bool

		gather := make(chan dispatchResult, NotifierQueueSize)
		for _, msg := range msgs {
			go func() {
				msg := msg
				dErr := n.dispatch(msg)

				if closed.Load() {
					return
				}

				gather <- dispatchResult{id: msg.ID, err: dErr}
				//fmt.Printf("[%s] >>>%s gathered: (%d of %d)\n", n.id, msg.ID, len(gather), cap(gather))
			}()
		}

		closeMe := make(chan bool, 1)
		time.AfterFunc(time.Second*2, func() {
			closeMe <- true
		})

		var wg sync.WaitGroup
		wg.Add(1)

		ticker := time.NewTicker(time.Millisecond * 100)
		defer ticker.Stop()

		go func() {
			defer wg.Done()

			for {
				select {
				case <-closeMe:
					closed.Store(true)
					close(gather)

					fmt.Printf("[%s] timeout!! release the lease\n", n.id)

					fmt.Printf("collected these %v messages though:\n", len(gather))

					for x := range gather {
						fmt.Printf("[%s]\t>>>%s: %v\n", n.id, x.id, x.err)
					}

					// update the messages that did return
					return
				case <-ticker.C:
					fmt.Printf("[%s] %d of %d collected\n", n.id, len(gather), cap(gather))
					if len(gather) == cap(gather) {
						fmt.Printf("all messages gathered!\n")
						close(gather)

						for x := range gather {
							fmt.Printf("[%s]\t>>>%s: %v\n", n.id, x.id, x.err)
						}

						return
					} else {
						//fmt.Printf("[%s] >>>%d of %d\n", n.id, len(gather), cap(gather))
						//time.Sleep(time.Millisecond * 10)
					}
				default:
				}
			}
		}()

		wg.Wait()
		fmt.Printf("[%s] END\n", n.id)
	}

	return nil
}

func (n *notifier) fetch(ctx context.Context) ([]database.NotificationMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, NotifierLeaseLength)
	deadline, _ := ctx.Deadline()
	defer cancel()

	msgs, err := n.db.AcquireNotificationMessages(ctx, database.AcquireNotificationMessagesParams{
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

func (n *notifier) dispatch(msg database.NotificationMessage) error {
	t := time.Duration(rand.IntN(500)) * time.Millisecond

	if rand.IntN(10) > 8 {
		t = t + time.Second*2
	}

	time.Sleep(t)

	if rand.IntN(10) < 5 {
		return xerrors.New(fmt.Sprintf("%s: oops", msg.ID))
	}
	return nil
}
