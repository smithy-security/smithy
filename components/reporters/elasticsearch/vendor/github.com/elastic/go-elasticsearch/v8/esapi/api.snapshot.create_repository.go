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
	"time"
)

func newSnapshotCreateRepositoryFunc(t Transport) SnapshotCreateRepository {
	return func(repository string, body io.Reader, o ...func(*SnapshotCreateRepositoryRequest)) (*Response, error) {
		var r = SnapshotCreateRepositoryRequest{Repository: repository, Body: body}
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

// SnapshotCreateRepository creates a repository.
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/master/modules-snapshots.html.
type SnapshotCreateRepository func(repository string, body io.Reader, o ...func(*SnapshotCreateRepositoryRequest)) (*Response, error)

// SnapshotCreateRepositoryRequest configures the Snapshot Create Repository API request.
type SnapshotCreateRepositoryRequest struct {
	Body io.Reader

	Repository string

	MasterTimeout time.Duration
	Timeout       time.Duration
	Verify        *bool

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r SnapshotCreateRepositoryRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "snapshot.create_repository")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "PUT"

	path.Grow(7 + 1 + len("_snapshot") + 1 + len(r.Repository))
	path.WriteString("http://")
	path.WriteString("/")
	path.WriteString("_snapshot")
	path.WriteString("/")
	path.WriteString(r.Repository)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.RecordPathPart(ctx, "repository", r.Repository)
	}

	params = make(map[string]string)

	if r.MasterTimeout != 0 {
		params["master_timeout"] = formatDuration(r.MasterTimeout)
	}

	if r.Timeout != 0 {
		params["timeout"] = formatDuration(r.Timeout)
	}

	if r.Verify != nil {
		params["verify"] = strconv.FormatBool(*r.Verify)
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
		instrument.BeforeRequest(req, "snapshot.create_repository")
		if reader := instrument.RecordRequestBody(ctx, "snapshot.create_repository", r.Body); reader != nil {
			req.Body = reader
		}
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "snapshot.create_repository")
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
func (f SnapshotCreateRepository) WithContext(v context.Context) func(*SnapshotCreateRepositoryRequest) {
	return func(r *SnapshotCreateRepositoryRequest) {
		r.ctx = v
	}
}

// WithMasterTimeout - explicit operation timeout for connection to master node.
func (f SnapshotCreateRepository) WithMasterTimeout(v time.Duration) func(*SnapshotCreateRepositoryRequest) {
	return func(r *SnapshotCreateRepositoryRequest) {
		r.MasterTimeout = v
	}
}

// WithTimeout - explicit operation timeout.
func (f SnapshotCreateRepository) WithTimeout(v time.Duration) func(*SnapshotCreateRepositoryRequest) {
	return func(r *SnapshotCreateRepositoryRequest) {
		r.Timeout = v
	}
}

// WithVerify - whether to verify the repository after creation.
func (f SnapshotCreateRepository) WithVerify(v bool) func(*SnapshotCreateRepositoryRequest) {
	return func(r *SnapshotCreateRepositoryRequest) {
		r.Verify = &v
	}
}

// WithPretty makes the response body pretty-printed.
func (f SnapshotCreateRepository) WithPretty() func(*SnapshotCreateRepositoryRequest) {
	return func(r *SnapshotCreateRepositoryRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f SnapshotCreateRepository) WithHuman() func(*SnapshotCreateRepositoryRequest) {
	return func(r *SnapshotCreateRepositoryRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f SnapshotCreateRepository) WithErrorTrace() func(*SnapshotCreateRepositoryRequest) {
	return func(r *SnapshotCreateRepositoryRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f SnapshotCreateRepository) WithFilterPath(v ...string) func(*SnapshotCreateRepositoryRequest) {
	return func(r *SnapshotCreateRepositoryRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f SnapshotCreateRepository) WithHeader(h map[string]string) func(*SnapshotCreateRepositoryRequest) {
	return func(r *SnapshotCreateRepositoryRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f SnapshotCreateRepository) WithOpaqueID(s string) func(*SnapshotCreateRepositoryRequest) {
	return func(r *SnapshotCreateRepositoryRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
