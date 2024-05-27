package notifications_test

import (
	"context"
	"testing"

	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/notifications"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestStuff(t *testing.T) {
	n := notifications.NewManager(fakeDB{})
	require.NoError(t, n.Run(1))
}

type fakeDB struct{}

func (f fakeDB) AcquireNotificationMessages(ctx context.Context, params database.AcquireNotificationMessagesParams) ([]database.NotificationMessage, error) {
	return []database.NotificationMessage{
		{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
		},
		{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
		},
		{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
		},
		{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
		},
		{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
		},
		{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
		},
		{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
		},
		{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
		},
		{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
		},
		{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
		},
	}, nil
}
