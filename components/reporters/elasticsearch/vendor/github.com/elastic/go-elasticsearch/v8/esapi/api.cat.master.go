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
	"net/http"
	"strconv"
	"strings"
	"time"
)

func newCatMasterFunc(t Transport) CatMaster {
	return func(o ...func(*CatMasterRequest)) (*Response, error) {
		var r = CatMasterRequest{}
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

// CatMaster returns information about the master node.
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/master/cat-master.html.
type CatMaster func(o ...func(*CatMasterRequest)) (*Response, error)

// CatMasterRequest configures the Cat Master API request.
type CatMasterRequest struct {
	Format        string
	H             []string
	Help          *bool
	Local         *bool
	MasterTimeout time.Duration
	S             []string
	V             *bool

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r CatMasterRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "cat.master")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "GET"

	path.Grow(7 + len("/_cat/master"))
	path.WriteString("http://")
	path.WriteString("/_cat/master")

	params = make(map[string]string)

	if r.Format != "" {
		params["format"] = r.Format
	}

	if len(r.H) > 0 {
		params["h"] = strings.Join(r.H, ",")
	}

	if r.Help != nil {
		params["help"] = strconv.FormatBool(*r.Help)
	}

	if r.Local != nil {
		params["local"] = strconv.FormatBool(*r.Local)
	}

	if r.MasterTimeout != 0 {
		params["master_timeout"] = formatDuration(r.MasterTimeout)
	}

	if len(r.S) > 0 {
		params["s"] = strings.Join(r.S, ",")
	}

	if r.V != nil {
		params["v"] = strconv.FormatBool(*r.V)
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

	req, err := newRequest(method, path.String(), nil)
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

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.BeforeRequest(req, "cat.master")
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "cat.master")
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
func (f CatMaster) WithContext(v context.Context) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.ctx = v
	}
}

// WithFormat - a short version of the accept header, e.g. json, yaml.
func (f CatMaster) WithFormat(v string) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.Format = v
	}
}

// WithH - comma-separated list of column names to display.
func (f CatMaster) WithH(v ...string) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.H = v
	}
}

// WithHelp - return help information.
func (f CatMaster) WithHelp(v bool) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.Help = &v
	}
}

// WithLocal - return local information, do not retrieve the state from master node (default: false).
func (f CatMaster) WithLocal(v bool) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.Local = &v
	}
}

// WithMasterTimeout - explicit operation timeout for connection to master node.
func (f CatMaster) WithMasterTimeout(v time.Duration) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.MasterTimeout = v
	}
}

// WithS - comma-separated list of column names or column aliases to sort by.
func (f CatMaster) WithS(v ...string) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.S = v
	}
}

// WithV - verbose mode. display column headers.
func (f CatMaster) WithV(v bool) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.V = &v
	}
}

// WithPretty makes the response body pretty-printed.
func (f CatMaster) WithPretty() func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f CatMaster) WithHuman() func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f CatMaster) WithErrorTrace() func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f CatMaster) WithFilterPath(v ...string) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f CatMaster) WithHeader(h map[string]string) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f CatMaster) WithOpaqueID(s string) func(*CatMasterRequest) {
	return func(r *CatMasterRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
