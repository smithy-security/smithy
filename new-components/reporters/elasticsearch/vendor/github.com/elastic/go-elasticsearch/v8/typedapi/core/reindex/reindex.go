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

// Reindex documents.
// Copies documents from a source to a destination. The source can be any
// existing index, alias, or data stream. The destination must differ from the
// source. For example, you cannot reindex a data stream into itself.
package reindex

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
	"github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/conflicts"
)

// ErrBuildPath is returned in case of missing parameters within the build of the request.
var ErrBuildPath = errors.New("cannot build path, check for missing path parameters")

type Reindex struct {
	transport elastictransport.Interface

	headers http.Header
	values  url.Values
	path    url.URL

	raw io.Reader

	req      *Request
	deferred []func(request *Request) error
	buf      *gobytes.Buffer

	paramSet int

	spanStarted bool

	instrument elastictransport.Instrumentation
}

// NewReindex type alias for index.
type NewReindex func() *Reindex

// NewReindexFunc returns a new instance of Reindex with the provided transport.
// Used in the index of the library this allows to retrieve every apis in once place.
func NewReindexFunc(tp elastictransport.Interface) NewReindex {
	return func() *Reindex {
		n := New(tp)

		return n
	}
}

// Reindex documents.
// Copies documents from a source to a destination. The source can be any
// existing index, alias, or data stream. The destination must differ from the
// source. For example, you cannot reindex a data stream into itself.
//
// https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html
func New(tp elastictransport.Interface) *Reindex {
	r := &Reindex{
		transport: tp,
		values:    make(url.Values),
		headers:   make(http.Header),

		buf: gobytes.NewBuffer(nil),

		req: NewRequest(),
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
func (r *Reindex) Raw(raw io.Reader) *Reindex {
	r.raw = raw

	return r
}

// Request allows to set the request property with the appropriate payload.
func (r *Reindex) Request(req *Request) *Reindex {
	r.req = req

	return r
}

// HttpRequest returns the http.Request object built from the
// given parameters.
func (r *Reindex) HttpRequest(ctx context.Context) (*http.Request, error) {
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

		data, err := json.Marshal(r.req)

		if err != nil {
			return nil, fmt.Errorf("could not serialise request for Reindex: %w", err)
		}

		r.buf.Write(data)

	}

	if r.buf.Len() > 0 {
		r.raw = r.buf
	}

	r.path.Scheme = "http"

	switch {
	case r.paramSet == 0:
		path.WriteString("/")
		path.WriteString("_reindex")

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
			req.Header.Set("Content-Type", "application/vnd.elasticsearch+json;compatible-with=8")
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
func (r Reindex) Perform(providedCtx context.Context) (*http.Response, error) {
	var ctx context.Context
	if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
		if r.spanStarted == false {
			ctx := instrument.Start(providedCtx, "reindex")
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
		instrument.BeforeRequest(req, "reindex")
		if reader := instrument.RecordRequestBody(ctx, "reindex", r.raw); reader != nil {
			req.Body = reader
		}
	}
	res, err := r.transport.Perform(req)
	if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
		instrument.AfterRequest(req, "elasticsearch", "reindex")
	}
	if err != nil {
		localErr := fmt.Errorf("an error happened during the Reindex query execution: %w", err)
		if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
			instrument.RecordError(ctx, localErr)
		}
		return nil, localErr
	}

	return res, nil
}

// Do runs the request through the transport, handle the response and returns a reindex.Response
func (r Reindex) Do(providedCtx context.Context) (*Response, error) {
	var ctx context.Context
	r.spanStarted = true
	if instrument, ok := r.instrument.(elastictransport.Instrumentation); ok {
		ctx = instrument.Start(providedCtx, "reindex")
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

// Header set a key, value pair in the Reindex headers map.
func (r *Reindex) Header(key, value string) *Reindex {
	r.headers.Set(key, value)

	return r
}

// Refresh If `true`, the request refreshes affected shards to make this operation
// visible to search.
// API name: refresh
func (r *Reindex) Refresh(refresh bool) *Reindex {
	r.values.Set("refresh", strconv.FormatBool(refresh))

	return r
}

// RequestsPerSecond The throttle for this request in sub-requests per second.
// Defaults to no throttle.
// API name: requests_per_second
func (r *Reindex) RequestsPerSecond(requestspersecond string) *Reindex {
	r.values.Set("requests_per_second", requestspersecond)

	return r
}

// Scroll Specifies how long a consistent view of the index should be maintained for
// scrolled search.
// API name: scroll
func (r *Reindex) Scroll(duration string) *Reindex {
	r.values.Set("scroll", duration)

	return r
}

// Slices The number of slices this task should be divided into.
// Defaults to 1 slice, meaning the task isn’t sliced into subtasks.
// API name: slices
func (r *Reindex) Slices(slices string) *Reindex {
	r.values.Set("slices", slices)

	return r
}

// Timeout Period each indexing waits for automatic index creation, dynamic mapping
// updates, and waiting for active shards.
// API name: timeout
func (r *Reindex) Timeout(duration string) *Reindex {
	r.values.Set("timeout", duration)

	return r
}

// WaitForActiveShards The number of shard copies that must be active before proceeding with the
// operation.
// Set to `all` or any positive integer up to the total number of shards in the
// index (`number_of_replicas+1`).
// API name: wait_for_active_shards
func (r *Reindex) WaitForActiveShards(waitforactiveshards string) *Reindex {
	r.values.Set("wait_for_active_shards", waitforactiveshards)

	return r
}

// WaitForCompletion If `true`, the request blocks until the operation is complete.
// API name: wait_for_completion
func (r *Reindex) WaitForCompletion(waitforcompletion bool) *Reindex {
	r.values.Set("wait_for_completion", strconv.FormatBool(waitforcompletion))

	return r
}

// RequireAlias If `true`, the destination must be an index alias.
// API name: require_alias
func (r *Reindex) RequireAlias(requirealias bool) *Reindex {
	r.values.Set("require_alias", strconv.FormatBool(requirealias))

	return r
}

// ErrorTrace When set to `true` Elasticsearch will include the full stack trace of errors
// when they occur.
// API name: error_trace
func (r *Reindex) ErrorTrace(errortrace bool) *Reindex {
	r.values.Set("error_trace", strconv.FormatBool(errortrace))

	return r
}

// FilterPath Comma-separated list of filters in dot notation which reduce the response
// returned by Elasticsearch.
// API name: filter_path
func (r *Reindex) FilterPath(filterpaths ...string) *Reindex {
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
func (r *Reindex) Human(human bool) *Reindex {
	r.values.Set("human", strconv.FormatBool(human))

	return r
}

// Pretty If set to `true` the returned JSON will be "pretty-formatted". Only use
// this option for debugging only.
// API name: pretty
func (r *Reindex) Pretty(pretty bool) *Reindex {
	r.values.Set("pretty", strconv.FormatBool(pretty))

	return r
}

// Conflicts Set to proceed to continue reindexing even if there are conflicts.
// API name: conflicts
func (r *Reindex) Conflicts(conflicts conflicts.Conflicts) *Reindex {
	r.req.Conflicts = &conflicts

	return r
}

// Dest The destination you are copying to.
// API name: dest
func (r *Reindex) Dest(dest *types.ReindexDestination) *Reindex {

	r.req.Dest = *dest

	return r
}

// MaxDocs The maximum number of documents to reindex.
// API name: max_docs
func (r *Reindex) MaxDocs(maxdocs int64) *Reindex {

	r.req.MaxDocs = &maxdocs

	return r
}

// Script The script to run to update the document source or metadata when reindexing.
// API name: script
func (r *Reindex) Script(script *types.Script) *Reindex {

	r.req.Script = script

	return r
}

// API name: size
func (r *Reindex) Size(size int64) *Reindex {

	r.req.Size = &size

	return r
}

// Source The source you are copying from.
// API name: source
func (r *Reindex) Source(source *types.ReindexSource) *Reindex {

	r.req.Source = *source

	return r
}
