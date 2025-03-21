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

package reindex

import (
	"encoding/json"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8/typedapi/types"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/conflicts"
)

// Request holds the request body struct for the package reindex
//
// https://github.com/elastic/elasticsearch-specification/blob/2f823ff6fcaa7f3f0f9b990dc90512d8901e5d64/specification/_global/reindex/ReindexRequest.ts#L27-L104
type Request struct {

	// Conflicts Set to proceed to continue reindexing even if there are conflicts.
	Conflicts *conflicts.Conflicts `json:"conflicts,omitempty"`
	// Dest The destination you are copying to.
	Dest types.ReindexDestination `json:"dest"`
	// MaxDocs The maximum number of documents to reindex.
	MaxDocs *int64 `json:"max_docs,omitempty"`
	// Script The script to run to update the document source or metadata when reindexing.
	Script *types.Script `json:"script,omitempty"`
	Size   *int64        `json:"size,omitempty"`
	// Source The source you are copying from.
	Source types.ReindexSource `json:"source"`
}

// NewRequest returns a Request
func NewRequest() *Request {
	r := &Request{}

	return r
}

// FromJSON allows to load an arbitrary json into the request structure
func (r *Request) FromJSON(data string) (*Request, error) {
	var req Request
	err := json.Unmarshal([]byte(data), &req)

	if err != nil {
		return nil, fmt.Errorf("could not deserialise json into Reindex request: %w", err)
	}

	return &req, nil
}
