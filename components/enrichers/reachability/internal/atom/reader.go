package atom

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/atom/purl"
	"github.com/smithy-security/smithy/components/enrichers/reachability/internal/logging"
)

type (
	// Reader is responsible for managing how to read atom files and understand their contents.
	Reader struct {
		atomFileGlob string
		purlParser   *purl.Parser
	}

	// ReachablePurls maps reachable purls based on the report.
	ReachablePurls map[string]struct{}

	// Reachables is a slice of Reachable.
	Reachables []Reachable

	// Response maps the content of an atom reachability report in json format.
	Response struct {
		Reachables Reachables `json:"reachables"`
	}

	// Reachable represents an atom reachable result.
	Reachable struct {
		Flows []Flows  `json:"flows"`
		Purls []string `json:"purls"`
	}

	// Flows describes the flows on how to reach such reachable.
	Flows struct {
		ID                    int    `json:"id"`
		Label                 string `json:"label"`
		Name                  string `json:"name"`
		FullName              string `json:"fullName"`
		Signature             string `json:"signature"`
		IsExternal            bool   `json:"isExternal"`
		Code                  string `json:"code"`
		TypeFullName          string `json:"typeFullName"`
		ParentMethodName      string `json:"parentMethodName"`
		ParentMethodSignature string `json:"parentMethodSignature"`
		ParentFileName        string `json:"parentFileName"`
		ParentPackageName     string `json:"parentPackageName"`
		ParentClassName       string `json:"parentClassName"`
		LineNumber            int    `json:"lineNumber"`
		ColumnNumber          int    `json:"columnNumber"`
		Tags                  string `json:"tags"`
	}
)

// NewReader returns a new atom file reader.
func NewReader(atomFileGlob string, purlParser *purl.Parser) (*Reader, error) {
	switch {
	case atomFileGlob == "":
		return nil, errors.New("invalid empty atom file glob")
	case purlParser == nil:
		return nil, errors.New("invalid nil purl parser")
	}

	return &Reader{
		atomFileGlob: atomFileGlob,
		purlParser:   purlParser,
	}, nil
}

// Read deserialises the json content of the provided atom file into Reachables format.
func (r *Reader) Read(ctx context.Context) ([]*Response, error) {
	var responses []*Response

	matches, err := filepath.Glob(r.atomFileGlob)
	if err != nil {
		return nil, err
	}
	var fileNames []string
	for _, match := range matches {
		_, err := os.Stat(match)
		if err != nil {
			return nil, err
		}
		fileNames = append(fileNames, match)
	}

	if len(fileNames) == 0 {
		return nil, errors.Errorf("glob %s, matched no files", r.atomFileGlob)
	}

	logger := logging.FromContext(ctx)

	for _, file := range fileNames {
		logger.Info("processing atom file", slog.String("filename", file))

		b, err := os.ReadFile(file)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, errors.Errorf("atom output file '%s' not found", file)
			}
			return nil, errors.Errorf("failed to read atom output file '%s': %w", file, err)
		}

		logger.Debug("response read from filesystem", slog.String("response", string(b)))

		var res Response
		if err := json.Unmarshal(b, &res); err != nil {
			return nil, fmt.Errorf("failed to unmarshal atom response: %w", err)
		}
		responses = append(responses, &res)
	}
	return responses, nil
}

// ReachablePurls finds all the reachable purls presents in the atom reachability result.
func (r *Reader) ReachablePurls(ctx context.Context, reachables *Response) (ReachablePurls, error) {
	var (
		logger      = logging.FromContext(ctx)
		uniquePurls = make(map[string]struct{})
		finalPurls  = make(ReachablePurls)
	)

	for _, reachable := range reachables.Reachables {
		for _, p := range reachable.Purls {
			if _, ok := uniquePurls[p]; !ok {
				uniquePurls[p] = struct{}{}
				parsedPurls, err := r.purlParser.ParsePurl(p)
				if err != nil {
					logger.Error(
						"could not parse purl. Continuing...",
						slog.Any("purl", p),
					)
					continue
				}

				for _, pp := range parsedPurls {
					finalPurls[pp] = struct{}{}
				}
			}
		}
	}

	return finalPurls, nil
}

func (rp ReachablePurls) IsPurlReachable(purl string) bool {
	purl = strings.ToLower(purl)
	_, ok := rp[purl]
	return ok
}
