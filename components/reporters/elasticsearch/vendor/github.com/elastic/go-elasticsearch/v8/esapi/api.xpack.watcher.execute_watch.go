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
	"strconv"
	"strings"
)

func newWatcherExecuteWatchFunc(t Transport) WatcherExecuteWatch {
	return func(o ...func(*WatcherExecuteWatchRequest)) (*Response, error) {
		var r = WatcherExecuteWatchRequest{}
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

// WatcherExecuteWatch - Forces the execution of a stored watch.
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/current/watcher-api-execute-watch.html.
type WatcherExecuteWatch func(o ...func(*WatcherExecuteWatchRequest)) (*Response, error)

// WatcherExecuteWatchRequest configures the Watcher Execute Watch API request.
type WatcherExecuteWatchRequest struct {
	WatchID string

	Body io.Reader

	Debug *bool

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r WatcherExecuteWatchRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "watcher.execute_watch")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "PUT"

	path.Grow(7 + 1 + len("_watcher") + 1 + len("watch") + 1 + len(r.WatchID) + 1 + len("_execute"))
	path.WriteString("http://")
	path.WriteString("/")
	path.WriteString("_watcher")
	path.WriteString("/")
	path.WriteString("watch")
	if r.WatchID != "" {
		path.WriteString("/")
		path.WriteString(r.WatchID)
		if instrument, ok := r.instrument.(Instrumentation); ok {
			instrument.RecordPathPart(ctx, "id", r.WatchID)
		}
	}
	path.WriteString("/")
	path.WriteString("_execute")

	params = make(map[string]string)

	if r.Debug != nil {
		params["debug"] = strconv.FormatBool(*r.Debug)
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
		instrument.BeforeRequest(req, "watcher.execute_watch")
		if reader := instrument.RecordRequestBody(ctx, "watcher.execute_watch", r.Body); reader != nil {
			req.Body = reader
		}
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "watcher.execute_watch")
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
func (f WatcherExecuteWatch) WithContext(v context.Context) func(*WatcherExecuteWatchRequest) {
	return func(r *WatcherExecuteWatchRequest) {
		r.ctx = v
	}
}

// WithBody - Execution control.
func (f WatcherExecuteWatch) WithBody(v io.Reader) func(*WatcherExecuteWatchRequest) {
	return func(r *WatcherExecuteWatchRequest) {
		r.Body = v
	}
}

// WithWatchID - watch ID.
func (f WatcherExecuteWatch) WithWatchID(v string) func(*WatcherExecuteWatchRequest) {
	return func(r *WatcherExecuteWatchRequest) {
		r.WatchID = v
	}
}

// WithDebug - indicates whether the watch should execute in debug mode.
func (f WatcherExecuteWatch) WithDebug(v bool) func(*WatcherExecuteWatchRequest) {
	return func(r *WatcherExecuteWatchRequest) {
		r.Debug = &v
	}
}

// WithPretty makes the response body pretty-printed.
func (f WatcherExecuteWatch) WithPretty() func(*WatcherExecuteWatchRequest) {
	return func(r *WatcherExecuteWatchRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f WatcherExecuteWatch) WithHuman() func(*WatcherExecuteWatchRequest) {
	return func(r *WatcherExecuteWatchRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f WatcherExecuteWatch) WithErrorTrace() func(*WatcherExecuteWatchRequest) {
	return func(r *WatcherExecuteWatchRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f WatcherExecuteWatch) WithFilterPath(v ...string) func(*WatcherExecuteWatchRequest) {
	return func(r *WatcherExecuteWatchRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f WatcherExecuteWatch) WithHeader(h map[string]string) func(*WatcherExecuteWatchRequest) {
	return func(r *WatcherExecuteWatchRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f WatcherExecuteWatch) WithOpaqueID(s string) func(*WatcherExecuteWatchRequest) {
	return func(r *WatcherExecuteWatchRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
