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
)

func newLicenseGetFunc(t Transport) LicenseGet {
	return func(o ...func(*LicenseGetRequest)) (*Response, error) {
		var r = LicenseGetRequest{}
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

// LicenseGet - Retrieves licensing information for the cluster
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/master/get-license.html.
type LicenseGet func(o ...func(*LicenseGetRequest)) (*Response, error)

// LicenseGetRequest configures the License Get API request.
type LicenseGetRequest struct {
	AcceptEnterprise *bool
	Local            *bool

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r LicenseGetRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "license.get")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "GET"

	path.Grow(7 + len("/_license"))
	path.WriteString("http://")
	path.WriteString("/_license")

	params = make(map[string]string)

	if r.AcceptEnterprise != nil {
		params["accept_enterprise"] = strconv.FormatBool(*r.AcceptEnterprise)
	}

	if r.Local != nil {
		params["local"] = strconv.FormatBool(*r.Local)
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
		instrument.BeforeRequest(req, "license.get")
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "license.get")
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
func (f LicenseGet) WithContext(v context.Context) func(*LicenseGetRequest) {
	return func(r *LicenseGetRequest) {
		r.ctx = v
	}
}

// WithAcceptEnterprise - supported for backwards compatibility with 7.x. if this param is used it must be set to true.
func (f LicenseGet) WithAcceptEnterprise(v bool) func(*LicenseGetRequest) {
	return func(r *LicenseGetRequest) {
		r.AcceptEnterprise = &v
	}
}

// WithLocal - return local information, do not retrieve the state from master node (default: false).
func (f LicenseGet) WithLocal(v bool) func(*LicenseGetRequest) {
	return func(r *LicenseGetRequest) {
		r.Local = &v
	}
}

// WithPretty makes the response body pretty-printed.
func (f LicenseGet) WithPretty() func(*LicenseGetRequest) {
	return func(r *LicenseGetRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f LicenseGet) WithHuman() func(*LicenseGetRequest) {
	return func(r *LicenseGetRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f LicenseGet) WithErrorTrace() func(*LicenseGetRequest) {
	return func(r *LicenseGetRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f LicenseGet) WithFilterPath(v ...string) func(*LicenseGetRequest) {
	return func(r *LicenseGetRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f LicenseGet) WithHeader(h map[string]string) func(*LicenseGetRequest) {
	return func(r *LicenseGetRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f LicenseGet) WithOpaqueID(s string) func(*LicenseGetRequest) {
	return func(r *LicenseGetRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
