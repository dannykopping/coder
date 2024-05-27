package notifications

import (
	"context"

	"github.com/coder/coder/v2/coderd/database"
	"golang.org/x/sync/errgroup"
)

type Manager struct {
	db        Store
	notifiers []*notifier
}

type Store interface {
	AcquireNotificationMessages(ctx context.Context, params database.AcquireNotificationMessagesParams) ([]database.NotificationMessage, error)
}

func NewManager(db Store) *Manager {
	return &Manager{db: db}
}

func (m *Manager) Run(nc int) error {
	var eg errgroup.Group

	for i := 0; i < nc; i++ {
		eg.Go(func() error {
			n := newNotifier(m.db)
			m.notifiers = append(m.notifiers, n)
			return n.run()
		})
	}

	return eg.Wait()
}
