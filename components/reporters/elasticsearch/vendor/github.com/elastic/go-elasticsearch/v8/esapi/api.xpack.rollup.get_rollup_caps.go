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
	"strings"
)

func newRollupGetRollupCapsFunc(t Transport) RollupGetRollupCaps {
	return func(o ...func(*RollupGetRollupCapsRequest)) (*Response, error) {
		var r = RollupGetRollupCapsRequest{}
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

// RollupGetRollupCaps - Returns the capabilities of any rollup jobs that have been configured for a specific index or index pattern.
//
// This API is experimental.
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/master/rollup-get-rollup-caps.html.
type RollupGetRollupCaps func(o ...func(*RollupGetRollupCapsRequest)) (*Response, error)

// RollupGetRollupCapsRequest configures the Rollup Get Rollup Caps API request.
type RollupGetRollupCapsRequest struct {
	Index string

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r RollupGetRollupCapsRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "rollup.get_rollup_caps")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "GET"

	path.Grow(7 + 1 + len("_rollup") + 1 + len("data") + 1 + len(r.Index))
	path.WriteString("http://")
	path.WriteString("/")
	path.WriteString("_rollup")
	path.WriteString("/")
	path.WriteString("data")
	if r.Index != "" {
		path.WriteString("/")
		path.WriteString(r.Index)
		if instrument, ok := r.instrument.(Instrumentation); ok {
			instrument.RecordPathPart(ctx, "id", r.Index)
		}
	}

	params = make(map[string]string)

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
		instrument.BeforeRequest(req, "rollup.get_rollup_caps")
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "rollup.get_rollup_caps")
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
func (f RollupGetRollupCaps) WithContext(v context.Context) func(*RollupGetRollupCapsRequest) {
	return func(r *RollupGetRollupCapsRequest) {
		r.ctx = v
	}
}

// WithIndex - the ID of the index to check rollup capabilities on, or left blank for all jobs.
func (f RollupGetRollupCaps) WithIndex(v string) func(*RollupGetRollupCapsRequest) {
	return func(r *RollupGetRollupCapsRequest) {
		r.Index = v
	}
}

// WithPretty makes the response body pretty-printed.
func (f RollupGetRollupCaps) WithPretty() func(*RollupGetRollupCapsRequest) {
	return func(r *RollupGetRollupCapsRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f RollupGetRollupCaps) WithHuman() func(*RollupGetRollupCapsRequest) {
	return func(r *RollupGetRollupCapsRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f RollupGetRollupCaps) WithErrorTrace() func(*RollupGetRollupCapsRequest) {
	return func(r *RollupGetRollupCapsRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f RollupGetRollupCaps) WithFilterPath(v ...string) func(*RollupGetRollupCapsRequest) {
	return func(r *RollupGetRollupCapsRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f RollupGetRollupCaps) WithHeader(h map[string]string) func(*RollupGetRollupCapsRequest) {
	return func(r *RollupGetRollupCapsRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f RollupGetRollupCaps) WithOpaqueID(s string) func(*RollupGetRollupCapsRequest) {
	return func(r *RollupGetRollupCapsRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
