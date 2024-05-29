package dispatcher

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd/database"
)

type SMTPDispatcher struct{}

func (s *SMTPDispatcher) Send(ctx context.Context, input database.StringMap, title, body string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// TODO: implement real smtp dispatcher
	t := time.Duration(rand.IntN(500)) * time.Millisecond
	if rand.IntN(10) > 8 {
		t = t + time.Second*2
	}

	select {
	case <-ctx.Done():
		return xerrors.Errorf("dispatch prematurely aborted: %w", ctx.Err())
	case <-time.After(t):
	default:
	}

	if rand.IntN(10) < 5 {
		return xerrors.New(fmt.Sprintf("oops"))
	}
	return nil
}
