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
	"strings"
)

func newSecurityClearCachedRealmsFunc(t Transport) SecurityClearCachedRealms {
	return func(realms []string, o ...func(*SecurityClearCachedRealmsRequest)) (*Response, error) {
		var r = SecurityClearCachedRealmsRequest{Realms: realms}
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

// SecurityClearCachedRealms - Evicts users from the user cache. Can completely clear the cache or evict specific users.
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-clear-cache.html.
type SecurityClearCachedRealms func(realms []string, o ...func(*SecurityClearCachedRealmsRequest)) (*Response, error)

// SecurityClearCachedRealmsRequest configures the Security Clear Cached Realms API request.
type SecurityClearCachedRealmsRequest struct {
	Realms []string

	Usernames []string

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r SecurityClearCachedRealmsRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "security.clear_cached_realms")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "POST"

	if len(r.Realms) == 0 {
		return nil, errors.New("realms is required and cannot be nil or empty")
	}

	path.Grow(7 + 1 + len("_security") + 1 + len("realm") + 1 + len(strings.Join(r.Realms, ",")) + 1 + len("_clear_cache"))
	path.WriteString("http://")
	path.WriteString("/")
	path.WriteString("_security")
	path.WriteString("/")
	path.WriteString("realm")
	path.WriteString("/")
	path.WriteString(strings.Join(r.Realms, ","))
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.RecordPathPart(ctx, "realms", strings.Join(r.Realms, ","))
	}
	path.WriteString("/")
	path.WriteString("_clear_cache")

	params = make(map[string]string)

	if len(r.Usernames) > 0 {
		params["usernames"] = strings.Join(r.Usernames, ",")
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
		instrument.BeforeRequest(req, "security.clear_cached_realms")
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "security.clear_cached_realms")
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
func (f SecurityClearCachedRealms) WithContext(v context.Context) func(*SecurityClearCachedRealmsRequest) {
	return func(r *SecurityClearCachedRealmsRequest) {
		r.ctx = v
	}
}

// WithUsernames - comma-separated list of usernames to clear from the cache.
func (f SecurityClearCachedRealms) WithUsernames(v ...string) func(*SecurityClearCachedRealmsRequest) {
	return func(r *SecurityClearCachedRealmsRequest) {
		r.Usernames = v
	}
}

// WithPretty makes the response body pretty-printed.
func (f SecurityClearCachedRealms) WithPretty() func(*SecurityClearCachedRealmsRequest) {
	return func(r *SecurityClearCachedRealmsRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f SecurityClearCachedRealms) WithHuman() func(*SecurityClearCachedRealmsRequest) {
	return func(r *SecurityClearCachedRealmsRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f SecurityClearCachedRealms) WithErrorTrace() func(*SecurityClearCachedRealmsRequest) {
	return func(r *SecurityClearCachedRealmsRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f SecurityClearCachedRealms) WithFilterPath(v ...string) func(*SecurityClearCachedRealmsRequest) {
	return func(r *SecurityClearCachedRealmsRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f SecurityClearCachedRealms) WithHeader(h map[string]string) func(*SecurityClearCachedRealmsRequest) {
	return func(r *SecurityClearCachedRealmsRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f SecurityClearCachedRealms) WithOpaqueID(s string) func(*SecurityClearCachedRealmsRequest) {
	return func(r *SecurityClearCachedRealmsRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
