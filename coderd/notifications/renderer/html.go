package renderer

import (
	html "html/template"
	"strings"

	"github.com/coder/coder/v2/coderd/database"
	"golang.org/x/xerrors"
)

type HTMLRenderer struct {
}

// Render parses the given template as an HTML template and renders it using Go's html/template package.
// TODO: consider performance impact
func (h *HTMLRenderer) Render(template string, input database.StringMap) (string, error) {
	tmpl, err := html.New("html").Parse(template)
	if err != nil {
		return "", xerrors.Errorf("template parse: %w", err)
	}

	var out strings.Builder
	if err = tmpl.Execute(&out, input); err != nil {
		return "", xerrors.Errorf("template execute: %w", err)
	}

	return out.String(), nil
}
