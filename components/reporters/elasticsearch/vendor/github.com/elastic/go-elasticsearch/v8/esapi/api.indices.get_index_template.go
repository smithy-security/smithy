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

func newIndicesGetIndexTemplateFunc(t Transport) IndicesGetIndexTemplate {
	return func(o ...func(*IndicesGetIndexTemplateRequest)) (*Response, error) {
		var r = IndicesGetIndexTemplateRequest{}
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

// IndicesGetIndexTemplate returns an index template.
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/master/indices-get-template.html.
type IndicesGetIndexTemplate func(o ...func(*IndicesGetIndexTemplateRequest)) (*Response, error)

// IndicesGetIndexTemplateRequest configures the Indices Get Index Template API request.
type IndicesGetIndexTemplateRequest struct {
	Name string

	FlatSettings    *bool
	IncludeDefaults *bool
	Local           *bool
	MasterTimeout   time.Duration

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r IndicesGetIndexTemplateRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "indices.get_index_template")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "GET"

	path.Grow(7 + 1 + len("_index_template") + 1 + len(r.Name))
	path.WriteString("http://")
	path.WriteString("/")
	path.WriteString("_index_template")
	if r.Name != "" {
		path.WriteString("/")
		path.WriteString(r.Name)
		if instrument, ok := r.instrument.(Instrumentation); ok {
			instrument.RecordPathPart(ctx, "name", r.Name)
		}
	}

	params = make(map[string]string)

	if r.FlatSettings != nil {
		params["flat_settings"] = strconv.FormatBool(*r.FlatSettings)
	}

	if r.IncludeDefaults != nil {
		params["include_defaults"] = strconv.FormatBool(*r.IncludeDefaults)
	}

	if r.Local != nil {
		params["local"] = strconv.FormatBool(*r.Local)
	}

	if r.MasterTimeout != 0 {
		params["master_timeout"] = formatDuration(r.MasterTimeout)
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
		instrument.BeforeRequest(req, "indices.get_index_template")
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "indices.get_index_template")
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
func (f IndicesGetIndexTemplate) WithContext(v context.Context) func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		r.ctx = v
	}
}

// WithName - a pattern that returned template names must match.
func (f IndicesGetIndexTemplate) WithName(v string) func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		r.Name = v
	}
}

// WithFlatSettings - return settings in flat format (default: false).
func (f IndicesGetIndexTemplate) WithFlatSettings(v bool) func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		r.FlatSettings = &v
	}
}

// WithIncludeDefaults - return all relevant default configurations for the index template (default: false).
func (f IndicesGetIndexTemplate) WithIncludeDefaults(v bool) func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		r.IncludeDefaults = &v
	}
}

// WithLocal - return local information, do not retrieve the state from master node (default: false).
func (f IndicesGetIndexTemplate) WithLocal(v bool) func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		r.Local = &v
	}
}

// WithMasterTimeout - explicit operation timeout for connection to master node.
func (f IndicesGetIndexTemplate) WithMasterTimeout(v time.Duration) func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		r.MasterTimeout = v
	}
}

// WithPretty makes the response body pretty-printed.
func (f IndicesGetIndexTemplate) WithPretty() func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f IndicesGetIndexTemplate) WithHuman() func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f IndicesGetIndexTemplate) WithErrorTrace() func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f IndicesGetIndexTemplate) WithFilterPath(v ...string) func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f IndicesGetIndexTemplate) WithHeader(h map[string]string) func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f IndicesGetIndexTemplate) WithOpaqueID(s string) func(*IndicesGetIndexTemplateRequest) {
	return func(r *IndicesGetIndexTemplateRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
