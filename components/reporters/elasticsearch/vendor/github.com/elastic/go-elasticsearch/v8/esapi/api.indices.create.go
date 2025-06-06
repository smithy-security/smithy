// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//
// Code generated from specification version 8.17.0: DO NOT EDIT

package esapi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

func newIndicesCreateFunc(t Transport) IndicesCreate {
	return func(index string, o ...func(*IndicesCreateRequest)) (*Response, error) {
		var r = IndicesCreateRequest{Index: index}
		for _, f := range o {
			f(&r)
		}

		if transport, ok := t.(Instrumented); ok {
			r.instrument = transport.InstrumentationEnabled()
		}

		return r.Do(r.ctx, t)
	}
}

// ----- API Definition -------------------------------------------------------

// IndicesCreate creates an index with optional settings and mappings.
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/master/indices-create-index.html.
type IndicesCreate func(index string, o ...func(*IndicesCreateRequest)) (*Response, error)

// IndicesCreateRequest configures the Indices Create API request.
type IndicesCreateRequest struct {
	Index string

	Body io.Reader

	MasterTimeout       time.Duration
	Timeout             time.Duration
	WaitForActiveShards string

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r IndicesCreateRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "indices.create")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "PUT"

	path.Grow(7 + 1 + len(r.Index))
	path.WriteString("http://")
	path.WriteString("/")
	path.WriteString(r.Index)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.RecordPathPart(ctx, "index", r.Index)
	}

	params = make(map[string]string)

	if r.MasterTimeout != 0 {
		params["master_timeout"] = formatDuration(r.MasterTimeout)
	}

	if r.Timeout != 0 {
		params["timeout"] = formatDuration(r.Timeout)
	}

	if r.WaitForActiveShards != "" {
		params["wait_for_active_shards"] = r.WaitForActiveShards
	}

	if r.Pretty {
		params["pretty"] = "true"
	}

	if r.Human {
		params["human"] = "true"
	}

	if r.ErrorTrace {
		params["error_trace"] = "true"
	}

	if len(r.FilterPath) > 0 {
		params["filter_path"] = strings.Join(r.FilterPath, ",")
	}

	req, err := newRequest(method, path.String(), r.Body)
	if err != nil {
		if instrument, ok := r.instrument.(Instrumentation); ok {
			instrument.RecordError(ctx, err)
		}
		return nil, err
	}

	if len(params) > 0 {
		q := req.URL.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	if len(r.Header) > 0 {
		if len(req.Header) == 0 {
			req.Header = r.Header
		} else {
			for k, vv := range r.Header {
				for _, v := range vv {
					req.Header.Add(k, v)
				}
			}
		}
	}

	if r.Body != nil && req.Header.Get(headerContentType) == "" {
		req.Header[headerContentType] = headerContentTypeJSON
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.BeforeRequest(req, "indices.create")
		if reader := instrument.RecordRequestBody(ctx, "indices.create", r.Body); reader != nil {
			req.Body = reader
		}
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "indices.create")
	}
	if err != nil {
		if instrument, ok := r.instrument.(Instrumentation); ok {
			instrument.RecordError(ctx, err)
		}
		return nil, err
	}

	response := Response{
		StatusCode: res.StatusCode,
		Body:       res.Body,
		Header:     res.Header,
	}

	return &response, nil
}

// WithContext sets the request context.
func (f IndicesCreate) WithContext(v context.Context) func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		r.ctx = v
	}
}

// WithBody - The configuration for the index (`settings` and `mappings`).
func (f IndicesCreate) WithBody(v io.Reader) func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		r.Body = v
	}
}

// WithMasterTimeout - specify timeout for connection to master.
func (f IndicesCreate) WithMasterTimeout(v time.Duration) func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		r.MasterTimeout = v
	}
}

// WithTimeout - explicit operation timeout.
func (f IndicesCreate) WithTimeout(v time.Duration) func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		r.Timeout = v
	}
}

// WithWaitForActiveShards - set the number of active shards to wait for before the operation returns..
func (f IndicesCreate) WithWaitForActiveShards(v string) func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		r.WaitForActiveShards = v
	}
}

// WithPretty makes the response body pretty-printed.
func (f IndicesCreate) WithPretty() func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f IndicesCreate) WithHuman() func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f IndicesCreate) WithErrorTrace() func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f IndicesCreate) WithFilterPath(v ...string) func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f IndicesCreate) WithHeader(h map[string]string) func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f IndicesCreate) WithOpaqueID(s string) func(*IndicesCreateRequest) {
	return func(r *IndicesCreateRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
