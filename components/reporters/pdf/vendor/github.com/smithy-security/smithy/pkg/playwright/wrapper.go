package wrapper

import (
	"fmt"

	"github.com/playwright-community/playwright-go"
)

// Wrapper is the wrapper interface that allows the playwright client to be pluggable
type Wrapper interface {
	Stop() error
	GetPDFOfPage(string, string) ([]byte, error)
}

// Client is the wrapper around google's go-github client
type Client struct {
	playwright *playwright.Playwright
}

// NewClient returns an actual github client
func NewClient() (Client, error) {
	pw, err := playwright.Run()
	if err != nil {
		return Client{}, err
	}
	// create new playwright client
	return Client{
		playwright: pw,
	}, nil
}

func (c Client) Stop() error {
	return c.playwright.Stop()
}

func (c Client) GetPDFOfPage(page, storePath string) ([]byte, error) {
	browser, err := c.playwright.Chromium.Launch()
	if err != nil {
		return nil, err
	}

	currentContext, err := browser.NewContext()
	if err != nil {
		return nil, err
	}

	newPage, err := currentContext.NewPage()
	if err != nil {
		return nil, err
	}

	if _, err = newPage.Goto(page); err != nil {
		return nil, fmt.Errorf("could not goto page %s in the browser: %w", page, err)
	}

	return newPage.PDF(playwright.PagePdfOptions{
		Path: playwright.String(storePath),
	})
}
