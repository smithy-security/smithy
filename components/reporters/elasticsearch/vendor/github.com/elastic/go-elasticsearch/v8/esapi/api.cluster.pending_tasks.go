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

func newClusterPendingTasksFunc(t Transport) ClusterPendingTasks {
	return func(o ...func(*ClusterPendingTasksRequest)) (*Response, error) {
		var r = ClusterPendingTasksRequest{}
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

// ClusterPendingTasks returns a list of any cluster-level changes (e.g. create index, update mapping,
// allocate or fail shard) which have not yet been executed.
//
// See full documentation at https://www.elastic.co/guide/en/elasticsearch/reference/master/cluster-pending.html.
type ClusterPendingTasks func(o ...func(*ClusterPendingTasksRequest)) (*Response, error)

// ClusterPendingTasksRequest configures the Cluster Pending Tasks API request.
type ClusterPendingTasksRequest struct {
	Local         *bool
	MasterTimeout time.Duration

	Pretty     bool
	Human      bool
	ErrorTrace bool
	FilterPath []string

	Header http.Header

	ctx context.Context

	instrument Instrumentation
}

// Do executes the request and returns response or error.
func (r ClusterPendingTasksRequest) Do(providedCtx context.Context, transport Transport) (*Response, error) {
	var (
		method string
		path   strings.Builder
		params map[string]string
		ctx    context.Context
	)

	if instrument, ok := r.instrument.(Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "cluster.pending_tasks")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	method = "GET"

	path.Grow(7 + len("/_cluster/pending_tasks"))
	path.WriteString("http://")
	path.WriteString("/_cluster/pending_tasks")

	params = make(map[string]string)

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
		instrument.BeforeRequest(req, "cluster.pending_tasks")
	}
	res, err := transport.Perform(req)
	if instrument, ok := r.instrument.(Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "cluster.pending_tasks")
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
func (f ClusterPendingTasks) WithContext(v context.Context) func(*ClusterPendingTasksRequest) {
	return func(r *ClusterPendingTasksRequest) {
		r.ctx = v
	}
}

// WithLocal - return local information, do not retrieve the state from master node (default: false).
func (f ClusterPendingTasks) WithLocal(v bool) func(*ClusterPendingTasksRequest) {
	return func(r *ClusterPendingTasksRequest) {
		r.Local = &v
	}
}

// WithMasterTimeout - specify timeout for connection to master.
func (f ClusterPendingTasks) WithMasterTimeout(v time.Duration) func(*ClusterPendingTasksRequest) {
	return func(r *ClusterPendingTasksRequest) {
		r.MasterTimeout = v
	}
}

// WithPretty makes the response body pretty-printed.
func (f ClusterPendingTasks) WithPretty() func(*ClusterPendingTasksRequest) {
	return func(r *ClusterPendingTasksRequest) {
		r.Pretty = true
	}
}

// WithHuman makes statistical values human-readable.
func (f ClusterPendingTasks) WithHuman() func(*ClusterPendingTasksRequest) {
	return func(r *ClusterPendingTasksRequest) {
		r.Human = true
	}
}

// WithErrorTrace includes the stack trace for errors in the response body.
func (f ClusterPendingTasks) WithErrorTrace() func(*ClusterPendingTasksRequest) {
	return func(r *ClusterPendingTasksRequest) {
		r.ErrorTrace = true
	}
}

// WithFilterPath filters the properties of the response body.
func (f ClusterPendingTasks) WithFilterPath(v ...string) func(*ClusterPendingTasksRequest) {
	return func(r *ClusterPendingTasksRequest) {
		r.FilterPath = v
	}
}

// WithHeader adds the headers to the HTTP request.
func (f ClusterPendingTasks) WithHeader(h map[string]string) func(*ClusterPendingTasksRequest) {
	return func(r *ClusterPendingTasksRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, v := range h {
			r.Header.Add(k, v)
		}
	}
}

// WithOpaqueID adds the X-Opaque-Id header to the HTTP request.
func (f ClusterPendingTasks) WithOpaqueID(s string) func(*ClusterPendingTasksRequest) {
	return func(r *ClusterPendingTasksRequest) {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("X-Opaque-Id", s)
	}
}
