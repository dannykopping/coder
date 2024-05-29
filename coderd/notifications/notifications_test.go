package notifications_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"cdr.dev/slog"
	"cdr.dev/slog/sloggers/slogtest"

	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/notifications"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestStuff(t *testing.T) {
	n := notifications.NewManager(fakeDB{})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		require.ErrorIs(t, n.Run(ctx, 3), context.Canceled)
	}()

	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Second * 3):
		t.Logf("\n\n\n\nCANCELED\n\n\n\n")
		cancel()
	case <-time.After(time.Second * 5):
		t.Logf("\n\n\n\nSTOPPED\n\n\n\n")
		n.Stop()
	}

	wg.Wait()
}

type fakeDB struct{}

func (f fakeDB) AcquireNotificationMessages(ctx context.Context, params database.AcquireNotificationMessagesParams) ([]database.AcquireNotificationMessagesRow, error) {
	out := make([]database.AcquireNotificationMessagesRow, 10)
	for i := 0; i < 10; i++ {
		out = append(out, database.AcquireNotificationMessagesRow{
			ID:                     uuid.New(),
			Status:                 database.NotificationMessageStatusEnqueued,
			NotificationTemplateID: uuid.New(),
			BodyTemplate:           "body with {{.variable}}",
			TitleTemplate:          "title with {{.variable}}",
			Receiver:               database.NotificationReceiverSmtp,
			Input: map[string]string{
				"id":       fmt.Sprintf("%d", i),
				"variable": fmt.Sprintf("ITEM %d", i+1),
			},
		})
	}
	return out, nil
}
