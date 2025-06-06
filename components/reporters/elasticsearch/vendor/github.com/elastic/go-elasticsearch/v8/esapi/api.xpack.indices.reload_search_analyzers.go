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
	"errors"
	"net/http"
	"strconv"
	"strings"
)

func newIndicesReloadSearchAnalyzersFunc(t Transport) IndicesReloadSearchAnalyzers {
	return func(index []string, o ...func(*IndicesReloadSearchAnalyzersRequest)) (*Response, error) {
		var r = IndicesReloadSearchAnalyzersRequest{Index: index}
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

// IndicesReloadSearchAnalyzers - Reloads an index's search analyzers and their resources.
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/master/indices-reload-analyzers.html.
type IndicesReloadSearchAnalyzers func(index []string, o ...func(*IndicesReloadSearchAnalyzersRequest)) (*Response, error)

// IndicesReloadSearchAnalyzersRequest configures the Indices Reload Search Analyzers API request.
type IndicesReloadSearchAnalyzersRequest struct {
	Index []string

	AllowNoIndices    *bool
	ExpandWildcards   string
	IgnoreUnavailable *bool
	Resource          string

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r IndicesReloadSearchAnalyzersRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "indices.reload_search_analyzers")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "POST"

	if len(r.Index) == 0 {
		return nil, errors.New("index is required and cannot be nil or empty")
	}

	path.Grow(7 + 1 + len(strings.Join(r.Index, ",")) + 1 + len("_reload_search_analyzers"))
	path.WriteString("http://")
	path.WriteString("/")
	path.WriteString(strings.Join(r.Index, ","))
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.RecordPathPart(ctx, "index", strings.Join(r.Index, ","))
	}
	path.WriteString("/")
	path.WriteString("_reload_search_analyzers")

	params = make(map[string]string)

	if r.AllowNoIndices != nil {
		params["allow_no_indices"] = strconv.FormatBool(*r.AllowNoIndices)
	}

	if r.ExpandWildcards != "" {
		params["expand_wildcards"] = r.ExpandWildcards
	}

	if r.IgnoreUnavailable != nil {
		params["ignore_unavailable"] = strconv.FormatBool(*r.IgnoreUnavailable)
	}

	if r.Resource != "" {
		params["resource"] = r.Resource
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
		instrument.BeforeRequest(req, "indices.reload_search_analyzers")
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "indices.reload_search_analyzers")
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
func (f IndicesReloadSearchAnalyzers) WithContext(v context.Context) func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		r.ctx = v
	}
}

// WithAllowNoIndices - whether to ignore if a wildcard indices expression resolves into no concrete indices. (this includes `_all` string or when no indices have been specified).
func (f IndicesReloadSearchAnalyzers) WithAllowNoIndices(v bool) func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		r.AllowNoIndices = &v
	}
}

// WithExpandWildcards - whether to expand wildcard expression to concrete indices that are open, closed or both..
func (f IndicesReloadSearchAnalyzers) WithExpandWildcards(v string) func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		r.ExpandWildcards = v
	}
}

// WithIgnoreUnavailable - whether specified concrete indices should be ignored when unavailable (missing or closed).
func (f IndicesReloadSearchAnalyzers) WithIgnoreUnavailable(v bool) func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		r.IgnoreUnavailable = &v
	}
}

// WithResource - changed resource to reload analyzers from if applicable.
func (f IndicesReloadSearchAnalyzers) WithResource(v string) func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		r.Resource = v
	}
}

// WithPretty makes the response body pretty-printed.
func (f IndicesReloadSearchAnalyzers) WithPretty() func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f IndicesReloadSearchAnalyzers) WithHuman() func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f IndicesReloadSearchAnalyzers) WithErrorTrace() func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f IndicesReloadSearchAnalyzers) WithFilterPath(v ...string) func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f IndicesReloadSearchAnalyzers) WithHeader(h map[string]string) func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f IndicesReloadSearchAnalyzers) WithOpaqueID(s string) func(*IndicesReloadSearchAnalyzersRequest) {
	return func(r *IndicesReloadSearchAnalyzersRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
