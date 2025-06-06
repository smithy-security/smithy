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

// Code generated from the elasticsearch-specification DO NOT EDIT.
// https://github.com/elastic/elasticsearch-specification/tree/2f823ff6fcaa7f3f0f9b990dc90512d8901e5d64

// Bulk index or delete documents.
// Performs multiple indexing or delete operations in a single API call.
// This reduces overhead and can greatly increase indexing speed.
package bulk

import (
	gobytes "bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/elastic/elastic-transport-go/v8/elastictransport"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/refresh"
)

const (
	indexMask = iota + 1
)

// ErrBuildPath is returned in case of missing parameters within the build of the request.
var ErrBuildPath = errors.New("cannot build path, check for missing path parameters")

type Bulk struct {
	transport elastictransport.Interface

	headers http.Header
	values  url.Values
	path    url.URL

	raw io.Reader

	req      *Request
	deferred []func(request *Request) error
	buf      *gobytes.Buffer

	paramSet int

	index string

	spanStarted bool

	instrument elastictransport.Instrumentation
}

// NewBulk type alias for index.
type NewBulk func() *Bulk

// NewBulkFunc returns a new instance of Bulk with the provided transport.
// Used in the index of the library this allows to retrieve every apis in once place.
func NewBulkFunc(tp elastictransport.Interface) NewBulk {
	return func() *Bulk {
		n := New(tp)

		return n
	}
}

// Bulk index or delete documents.
// Performs multiple indexing or delete operations in a single API call.
// This reduces overhead and can greatly increase indexing speed.
//
// https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
func New(tp elastictransport.Interface) *Bulk {
	r := &Bulk{
		transport: tp,
		values:    make(url.Values),
		headers:   make(http.Header),

		buf: gobytes.NewBuffer(nil),
	}

	if instrumented, ok := r.transport.(elastictransport.Instrumented); ok {
		if instrument := instrumented.InstrumentationEnabled(); instrument != nil {
			r.instrument = instrument
		}
	}

	return r
}

// Raw takes a json payload as input which is then passed to the http.Request
// If specified Raw takes precedence on Request method.
func (r *Bulk) Raw(raw io.Reader) *Bulk {
	r.raw = raw

	return r
}

// Request allows to set the request property with the appropriate payload.
func (r *Bulk) Request(req *Request) *Bulk {
	r.req = req

	return r
}

// HttpRequest returns the http.Request object built from the
// given parameters.
func (r *Bulk) HttpRequest(ctx context.Context) (*http.Request, error) {
	var path strings.Builder
	var method string
	var req *http.Request

	var err error

	if len(r.deferred) > 0 {
		for _, f := range r.deferred {
			deferredErr := f(r.req)
			if deferredErr != nil {
				return nil, deferredErr
			}
		}
	}

	if r.raw == nil && r.req != nil {

		for _, elem := range *r.req {
			data, err := json.Marshal(elem)
			if err != nil {
				return nil, err
			}
			r.buf.Write(data)
			r.buf.Write([]byte("\n"))
		}

		if err != nil {
			return nil, fmt.Errorf("could not serialise request for Bulk: %w", err)
		}

	}

	if r.buf.Len() > 0 {
		r.raw = r.buf
	}

	r.path.Scheme = "http"

	switch {
	case r.paramSet == 0:
		path.WriteString("/")
		path.WriteString("_bulk")

		method = http.MethodPost
	case r.paramSet == indexMask:
		path.WriteString("/")

		if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
			instrument.RecordPathPart(ctx, "index", r.index)
		}
		path.WriteString(r.index)
		path.WriteString("/")
		path.WriteString("_bulk")

		method = http.MethodPost
	}

	r.path.Path = path.String()
	r.path.RawQuery = r.values.Encode()

	if r.path.Path == "" {
		return nil, ErrBuildPath
	}

	if ctx != nil {
		req, err = http.NewRequestWithContext(ctx, method, r.path.String(), r.raw)
	} else {
		req, err = http.NewRequest(method, r.path.String(), r.raw)
	}

	req.Header = r.headers.Clone()

	if req.Header.Get("Content-Type") == "" {
		if r.raw != nil {
			req.Header.Set("Content-Type", "application/vnd.elasticsearch+x-ndjson;compatible-with=8")
		}
	}

	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/vnd.elasticsearch+json;compatible-with=8")
	}

	if err != nil {
		return req, fmt.Errorf("could not build http.Request: %w", err)
	}

	return req, nil
}

// Perform runs the http.Request through the provided transport and returns an http.Response.
func (r Bulk) Perform(providedCtx context.Context) (*http.Response, error) {
	var ctx context.Context
	if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
		if r.spanStarted == false {
			ctx := instrument.Start(providedCtx, "bulk")
			defer instrument.Close(ctx)
		}
	}
	if ctx == nil {
		ctx = providedCtx
	}

	req, err := r.HttpRequest(ctx)
	if err != nil {
		if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
			instrument.RecordError(ctx, err)
		}
		return nil, err
	}

	if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
		instrument.BeforeRequest(req, "bulk")
		if reader := instrument.RecordRequestBody(ctx, "bulk", r.raw); reader != nil {
			req.Body = reader
		}
	}
	res, err := r.transport.Perform(req)
	if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "bulk")
	}
	if err != nil {
		localErr := fmt.Errorf("an error happened during the Bulk query execution: %w", err)
		if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
			instrument.RecordError(ctx, localErr)
		}
		return nil, localErr
	}

	return res, nil
}

// Do runs the request through the transport, handle the response and returns a bulk.Response
func (r Bulk) Do(providedCtx context.Context) (*Response, error) {
	var ctx context.Context
	r.spanStarted = true
	if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "bulk")
		defer instrument.Close(ctx)
	}
	if ctx == nil {
		ctx = providedCtx
	}

	response := NewResponse()

	res, err := r.Perform(ctx)
	if err != nil {
		if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
			instrument.RecordError(ctx, err)
		}
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode < 299 {
		err = json.NewDecoder(res.Body).Decode(response)
		if err != nil {
			if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
				instrument.RecordError(ctx, err)
			}
			return nil, err
		}

		return response, nil
	}

	errorResponse := types.NewElasticsearchError()
	err = json.NewDecoder(res.Body).Decode(errorResponse)
	if err != nil {
		if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
			instrument.RecordError(ctx, err)
		}
		return nil, err
	}

	if errorResponse.Status == 0 {
		errorResponse.Status = res.StatusCode
	}

	if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
		instrument.RecordError(ctx, errorResponse)
	}
	return nil, errorResponse
}

// Header set a key, value pair in the Bulk headers map.
func (r *Bulk) Header(key, value string) *Bulk {
	r.headers.Set(key, value)

	return r
}

// Index Name of the data stream, index, or index alias to perform bulk actions on.
// API Name: index
func (r *Bulk) Index(index string) *Bulk {
	r.paramSet |= indexMask
	r.index = index

	return r
}

// ListExecutedPipelines If `true`, the response will include the ingest pipelines that were executed
// for each index or create.
// API name: list_executed_pipelines
func (r *Bulk) ListExecutedPipelines(listexecutedpipelines bool) *Bulk {
	r.values.Set("list_executed_pipelines", strconv.FormatBool(listexecutedpipelines))

	return r
}

// Pipeline ID of the pipeline to use to preprocess incoming documents.
// If the index has a default ingest pipeline specified, then setting the value
// to `_none` disables the default ingest pipeline for this request.
// If a final pipeline is configured it will always run, regardless of the value
// of this parameter.
// API name: pipeline
func (r *Bulk) Pipeline(pipeline string) *Bulk {
	r.values.Set("pipeline", pipeline)

	return r
}

// Refresh If `true`, Elasticsearch refreshes the affected shards to make this operation
// visible to search, if `wait_for` then wait for a refresh to make this
// operation visible to search, if `false` do nothing with refreshes.
// Valid values: `true`, `false`, `wait_for`.
// API name: refresh
func (r *Bulk) Refresh(refresh refresh.Refresh) *Bulk {
	r.values.Set("refresh", refresh.String())

	return r
}

// Routing Custom value used to route operations to a specific shard.
// API name: routing
func (r *Bulk) Routing(routing string) *Bulk {
	r.values.Set("routing", routing)

	return r
}

// Source_ `true` or `false` to return the `_source` field or not, or a list of fields
// to return.
// API name: _source
func (r *Bulk) Source_(sourceconfigparam string) *Bulk {
	r.values.Set("_source", sourceconfigparam)

	return r
}

// SourceExcludes_ A comma-separated list of source fields to exclude from the response.
// API name: _source_excludes
func (r *Bulk) SourceExcludes_(fields ...string) *Bulk {
	r.values.Set("_source_excludes", strings.Join(fields, ","))

	return r
}

// SourceIncludes_ A comma-separated list of source fields to include in the response.
// API name: _source_includes
func (r *Bulk) SourceIncludes_(fields ...string) *Bulk {
	r.values.Set("_source_includes", strings.Join(fields, ","))

	return r
}

// Timeout Period each action waits for the following operations: automatic index
// creation, dynamic mapping updates, waiting for active shards.
// API name: timeout
func (r *Bulk) Timeout(duration string) *Bulk {
	r.values.Set("timeout", duration)

	return r
}

// WaitForActiveShards The number of shard copies that must be active before proceeding with the
// operation.
// Set to all or any positive integer up to the total number of shards in the
// index (`number_of_replicas+1`).
// API name: wait_for_active_shards
func (r *Bulk) WaitForActiveShards(waitforactiveshards string) *Bulk {
	r.values.Set("wait_for_active_shards", waitforactiveshards)

	return r
}

// RequireAlias If `true`, the request’s actions must target an index alias.
// API name: require_alias
func (r *Bulk) RequireAlias(requirealias bool) *Bulk {
	r.values.Set("require_alias", strconv.FormatBool(requirealias))

	return r
}

// RequireDataStream If `true`, the request's actions must target a data stream (existing or
// to-be-created).
// API name: require_data_stream
func (r *Bulk) RequireDataStream(requiredatastream bool) *Bulk {
	r.values.Set("require_data_stream", strconv.FormatBool(requiredatastream))

	return r
}

// ErrorTrace When set to `true` Elasticsearch will include the full stack trace of errors
// when they occur.
// API name: error_trace
func (r *Bulk) ErrorTrace(errortrace bool) *Bulk {
	r.values.Set("error_trace", strconv.FormatBool(errortrace))

	return r
}

// FilterPath Comma-separated list of filters in dot notation which reduce the response
// returned by Elasticsearch.
// API name: filter_path
func (r *Bulk) FilterPath(filterpaths ...string) *Bulk {
	tmp := []string{}
	for _, item := range filterpaths {
		tmp = append(tmp, fmt.Sprintf("%v", item))
	}
	r.values.Set("filter_path", strings.Join(tmp, ","))

	return r
}

// Human When set to `true` will return statistics in a format suitable for humans.
// For example `"exists_time": "1h"` for humans and
// `"eixsts_time_in_millis": 3600000` for computers. When disabled the human
// readable values will be omitted. This makes sense for responses being
// consumed
// only by machines.
// API name: human
func (r *Bulk) Human(human bool) *Bulk {
	r.values.Set("human", strconv.FormatBool(human))

	return r
}

// Pretty If set to `true` the returned JSON will be "pretty-formatted". Only use
// this option for debugging only.
// API name: pretty
func (r *Bulk) Pretty(pretty bool) *Bulk {
	r.values.Set("pretty", strconv.FormatBool(pretty))

	return r
}
