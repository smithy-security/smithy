package reporter

import (
	"io"

	esv8 "github.com/elastic/go-elasticsearch/v8"
	esapiv8 "github.com/elastic/go-elasticsearch/v8/esapi"

	esv9 "github.com/elastic/go-elasticsearch/v9"
	esapiv9 "github.com/elastic/go-elasticsearch/v9/esapi"
)

// v8Client is a wrapper for the es v8 client
type v8Client struct {
	client *esv8.Client
}

// Index calls the underlying v8 client's Index method and wraps the response
func (a *v8Client) Index(index string, body io.Reader) (esResponse, error) {
	res, err := a.client.Index(index, body)
	if err != nil {
		return nil, err
	}
	return &v8EsAPIRes{res}, nil
}

// Info calls the underlying v8 client's Info method and wraps the response
func (a *v8Client) Info() (esResponse, error) {
	res, err := a.client.Info()
	if err != nil {
		return nil, err
	}
	return &v8EsAPIRes{res}, nil
}

// v8EsAPIRes wraps the v8 ES API
type v8EsAPIRes struct {
	res *esapiv8.Response
}

func (r *v8EsAPIRes) IsError() bool       { return r.res.IsError() }
func (r *v8EsAPIRes) String() string      { return r.res.String() }
func (r *v8EsAPIRes) StatusCode() int     { return r.res.StatusCode }
func (r *v8EsAPIRes) Body() io.ReadCloser { return r.res.Body }

// v9Client is a wrapper for the es v9 client
type v9Client struct {
	client *esv9.Client
}

// Index calls the underlying v9 client's Index method and wraps the response.
func (a *v9Client) Index(index string, body io.Reader) (esResponse, error) {
	res, err := a.client.Index(index, body)
	if err != nil {
		return nil, err
	}
	return &v9EsAPIRes{res}, nil
}

// Info calls the underlying v9 client's Info method and wraps the response
func (a *v9Client) Info() (esResponse, error) {
	res, err := a.client.Info()
	if err != nil {
		return nil, err
	}
	return &v9EsAPIRes{res}, nil
}

// v9EsAPIRes wraps the v9 ES API
type v9EsAPIRes struct {
	res *esapiv9.Response
}

func (r *v9EsAPIRes) IsError() bool       { return r.res.IsError() }
func (r *v9EsAPIRes) String() string      { return r.res.String() }
func (r *v9EsAPIRes) StatusCode() int     { return r.res.StatusCode }
func (r *v9EsAPIRes) Body() io.ReadCloser { return r.res.Body }
