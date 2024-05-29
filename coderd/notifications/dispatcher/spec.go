package dispatcher

import (
	"context"

	"github.com/coder/coder/v2/coderd/database"
)

type dispatcher interface {
	Send(ctx context.Context, input database.StringMap, title, body string) error
}
