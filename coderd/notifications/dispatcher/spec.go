package dispatcher

import (
	"context"

	"github.com/coder/coder/v2/coderd/database"
)

type dispatcher interface {
	Send(ctx context.Context, msg database.NotificationMessage, title, body string) error // TODO: don't use database type
}
