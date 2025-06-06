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

func newSecurityGetUserProfileFunc(t Transport) SecurityGetUserProfile {
	return func(uid []string, o ...func(*SecurityGetUserProfileRequest)) (*Response, error) {
		var r = SecurityGetUserProfileRequest{UID: uid}
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

// SecurityGetUserProfile - Retrieves user profiles for the given unique ID(s).
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-get-user-profile.html.
type SecurityGetUserProfile func(uid []string, o ...func(*SecurityGetUserProfileRequest)) (*Response, error)

// SecurityGetUserProfileRequest configures the Security Get User Profile API request.
type SecurityGetUserProfileRequest struct {
	UID []string

	Data []string

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r SecurityGetUserProfileRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "security.get_user_profile")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "GET"

	if len(r.UID) == 0 {
		return nil, errors.New("uid is required and cannot be nil or empty")
	}

	path.Grow(7 + 1 + len("_security") + 1 + len("profile") + 1 + len(strings.Join(r.UID, ",")))
	path.WriteString("http://")
	path.WriteString("/")
	path.WriteString("_security")
	path.WriteString("/")
	path.WriteString("profile")
	path.WriteString("/")
	path.WriteString(strings.Join(r.UID, ","))
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.RecordPathPart(ctx, "uid", strings.Join(r.UID, ","))
	}

	params = make(map[string]string)

	if len(r.Data) > 0 {
		params["data"] = strings.Join(r.Data, ",")
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
		instrument.BeforeRequest(req, "security.get_user_profile")
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "security.get_user_profile")
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
func (f SecurityGetUserProfile) WithContext(v context.Context) func(*SecurityGetUserProfileRequest) {
	return func(r *SecurityGetUserProfileRequest) {
		r.ctx = v
	}
}

// WithData - a list of keys for which the corresponding application data are retrieved..
func (f SecurityGetUserProfile) WithData(v ...string) func(*SecurityGetUserProfileRequest) {
	return func(r *SecurityGetUserProfileRequest) {
		r.Data = v
	}
}

// WithPretty makes the response body pretty-printed.
func (f SecurityGetUserProfile) WithPretty() func(*SecurityGetUserProfileRequest) {
	return func(r *SecurityGetUserProfileRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f SecurityGetUserProfile) WithHuman() func(*SecurityGetUserProfileRequest) {
	return func(r *SecurityGetUserProfileRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f SecurityGetUserProfile) WithErrorTrace() func(*SecurityGetUserProfileRequest) {
	return func(r *SecurityGetUserProfileRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f SecurityGetUserProfile) WithFilterPath(v ...string) func(*SecurityGetUserProfileRequest) {
	return func(r *SecurityGetUserProfileRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f SecurityGetUserProfile) WithHeader(h map[string]string) func(*SecurityGetUserProfileRequest) {
	return func(r *SecurityGetUserProfileRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f SecurityGetUserProfile) WithOpaqueID(s string) func(*SecurityGetUserProfileRequest) {
	return func(r *SecurityGetUserProfileRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
