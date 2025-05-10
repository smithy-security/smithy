package reporter

import (
	"bytes"
	_ "embed"
	"fmt"
	"path"
	"text/template"

	"github.com/go-errors/errors"
)

//go:embed thread.tpl
var threadTpl string

type ThreadData struct {
	NumFindings int
	RunName     string
	RunLink     string
}

func (r reporter) getThreadMsg(numFindings int) (string, error) {
	tpl, err := template.New("thread").Parse(threadTpl)
	if err != nil {
		return "", errors.Errorf("could not parse thread template: %w", err)
	}

	var (
		buf     bytes.Buffer
		runLink = fmt.Sprintf(
			"https://%s",
			path.Join(
				r.cfg.SmithyDashURL.Host,
				"instances",
				r.cfg.SmithyInstanceID,
			),
		)
	)

	if err := tpl.Execute(&buf, ThreadData{
		NumFindings: numFindings,
		RunName:     r.cfg.SmithyInstanceName,
		RunLink:     runLink,
	}); err != nil {
		return "", errors.Errorf("could not execute thread template: %w", err)
	}

	return buf.String(), nil
}
