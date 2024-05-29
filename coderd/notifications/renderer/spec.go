package renderer

import "github.com/coder/coder/v2/coderd/database"

type renderer interface {
	Render(template string, input database.StringMap) (string, error)
}
