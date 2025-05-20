package reporter

import (
	"bytes"
	_ "embed"
	"text/template"

	"github.com/go-errors/errors"
)

//go:embed thread.tpl
var threadTpl string

type ThreadData struct {
	NumFindings int
	RunName     string
}

func (r reporter) getThreadMsg(numFindings int) (string, error) {
	tpl, err := template.New("thread").Parse(threadTpl)
	if err != nil {
		return "", errors.Errorf("could not parse thread template: %w", err)
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, ThreadData{
		NumFindings: numFindings,
		RunName:     r.cfg.SmithyInstanceName,
	}); err != nil {
		return "", errors.Errorf("could not execute thread template: %w", err)
	}

	return buf.String(), nil
}
