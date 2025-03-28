// Package producers provides helper functions for writing Smithy compatible producers that parse tool outputs.
// Subdirectories in this package have more complete example usages of this package.
package producers

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	smithyapiv1 "github.com/smithy-security/smithy/api/proto/v1"
	components "github.com/smithy-security/smithy/deprecated-components"

	"github.com/package-url/packageurl-go"

	"github.com/smithy-security/smithy/pkg/putil"
)

var (
	// InResults represents incoming tool output.
	InResults string
	// OutFile points to the protobuf file where smithy results will be written.
	OutFile string
	// Append flag will append to the outfile instead of overwriting, useful when there's multiple inresults.
	Append bool
	// debug flag initializes the logger with a debug level
	debug bool
)

const (
	SourceDir = "/workspace/output/source-code/"
)

var fileTargetPattern = regexp.MustCompile(`^(.*?:.*?):(.*)$`)

// ParseFlags will parse the input flags for the producer and perform simple validation.
func ParseFlags() error {
	flag.StringVar(&InResults, "in", "", "")
	flag.StringVar(&OutFile, "out", "", "")
	flag.BoolVar(&debug, "debug", false, "turn on debug logging")
	flag.BoolVar(&Append, "append", false, "Append to output file instead of overwriting it")

	flag.Parse()
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})).With("scanID", os.Getenv(components.EnvSmithyScanID)))

	if InResults == "" {
		return fmt.Errorf("in is undefined")
	}
	if OutFile == "" {
		return fmt.Errorf("out is undefined")
	}
	return nil
}

// ReadInFile returns the contents of the file given by InResults.
func ReadInFile() ([]byte, error) {
	data, err := os.ReadFile(InResults)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// ParseMultiJSONMessages provides method to parse tool results in JSON format.
// It allows for parsing single JSON files with multiple JSON messages in them.
func ParseMultiJSONMessages(in []byte) ([]interface{}, error) {
	dec := json.NewDecoder(strings.NewReader(string(in)))
	var res []interface{}
	for {
		var item interface{}
		err := dec.Decode(&item)
		if errors.Is(err, io.EOF) {
			res = append(res, item)
			break
		} else if err != nil {
			return res, err
		}
		res = append(res, item)
	}
	return res, nil
}

// WriteSmithyOut provides a generic method to write the resulting protobuf to the output file.
func WriteSmithyOut(
	toolName string,
	issues []*smithyapiv1.Issue,
) error {
	source := getSource()
	cleanIssues := []*smithyapiv1.Issue{}
	for _, iss := range issues {
		iss.Description = strings.ReplaceAll(iss.Description, SourceDir, "")
		iss.Title = strings.ReplaceAll(iss.Title, SourceDir, "")
		iss.Target = strings.ReplaceAll(iss.Target, SourceDir, "")
		iss.Source = source
		cleanIssues = append(cleanIssues, iss)
		slog.Debug(fmt.Sprintf("found issue: %+v\n", iss))
	}
	scanStartTime, err := time.Parse(time.RFC3339, strings.TrimSpace(os.Getenv(components.EnvSmithyStartTime)))
	if err != nil {
		scanStartTime = time.Now().UTC()
	}
	scanUUUID := strings.TrimSpace(os.Getenv(components.EnvSmithyScanID))
	scanTagsStr := strings.TrimSpace(os.Getenv(components.EnvSmithyScanTags))
	scanTags := map[string]string{}
	err = json.Unmarshal([]byte(scanTagsStr), &scanTags)
	if err != nil {
		slog.Debug("scan does not have any tags", "err", err)
	}

	stat, err := os.Stat(OutFile)
	if Append && err == nil && stat.Size() > 0 {
		slog.Info(
			"appending",
			slog.Int("issues", len(cleanIssues)),
			slog.String("tool", toolName),
			slog.String("to", OutFile),
		)
		return putil.AppendResults(cleanIssues, OutFile)
	}
	return putil.WriteResults(toolName, cleanIssues, OutFile, scanUUUID, scanStartTime, scanTags)
}

func getSource() string {
	sourceMetaPath := filepath.Join(SourceDir, ".source.smithy")
	_, err := os.Stat(sourceMetaPath)
	if os.IsNotExist(err) {
		return "unknown"
	}

	dat, err := os.ReadFile(sourceMetaPath)
	if err != nil {
		slog.Error(err.Error())
	}
	return strings.TrimSpace(string(dat))
}

// GetPURLTarget returns a purl target string for a given package.
// This should be used as the `Issue.Target` field of SCA producers.
//
// Example: GetPURLTarget("deb", "debian", "curl", "7.68.0", nil, "")
func GetPURLTarget(purlType string, namespace string, name string, version string, qualifiers packageurl.Qualifiers, subpath string) string {
	return packageurl.NewPackageURL(purlType, namespace, name, version, qualifiers, subpath).ToString()
}

// EnsureValidPURLTarget takes a purl target string from an untrusted source,
// e.g. a tool output, and ensures it is a valid purl target
func EnsureValidPURLTarget(purlTarget string) (string, error) {
	instance, err := packageurl.FromString(purlTarget)
	if err != nil {
		return "", err
	}
	return instance.ToString(), nil
}

// GetFileTarget returns a file target string for a given file path.
// This should be used as the `Issue.Target` field of SAST producers.
// The root of the `filePath` should be the root of the scanned code.
//
// Example: GetFileTarget("src/main.go", 10, 20)
// Result: "file:///src/main.go:10-20"
func GetFileTarget(filePath string, startLine int, endLine int) string {
	if filePath == "" {
		return ""
	}
	url := url.URL{Scheme: "file", Path: filePath}

	return fmt.Sprintf("%s:%d-%d", url.String(), startLine, endLine)
}

// EnsureValidFileTarget takes a file target string from an untrusted source,
// e.g. a tool output, and ensures it is a valid file target.
// file:///path/to/file.txt:10-20
func EnsureValidFileTarget(fileTarget string) (string, error) {
	url, start, end, err := GetPartsFromFileTarget(fileTarget)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%d-%d", url.String(), start, end), nil
}

// GetPartsFromFileTarget takes a file target string and returns the parts.
// file:///path/to/file.txt:10-20
// Returns: url.URL, startLine, endLine, error
func GetPartsFromFileTarget(fileTarget string) (*url.URL, int, int, error) {
	parts := fileTargetPattern.FindStringSubmatch(fileTarget)
	if len(parts) != 3 {
		return nil, 0, 0, fmt.Errorf("invalid file target format: %s; MUST be file://path/to/file:start-end", fileTarget)
	}

	// Ensure the file URI is correct
	parsedURI, err := url.Parse(parts[1])
	if err != nil {
		return nil, 0, 0, err
	}
	if parsedURI.Scheme != "file" {
		return nil, 0, 0, fmt.Errorf("invalid file target scheme: %s; MUST be file://", parsedURI.Scheme)
	}

	// Ensure the URI points to a file, not a directory
	if filepath.Ext(parsedURI.Path) == "" {
		return nil, 0, 0, fmt.Errorf("invalid file target path: %s; MUST point to a file", parsedURI.Path)
	}

	// Ensure the line range is correct
	lineRange := strings.Split(parts[2], "-")
	if len(lineRange) != 2 {
		return nil, 0, 0, fmt.Errorf("invalid line range format: %s; MUST be start-end", parts[1])
	}
	start, err := strconv.Atoi(lineRange[0])
	if err != nil {
		return nil, 0, 0, fmt.Errorf("invalid start line: %s; MUST be an integer", lineRange[0])
	}
	end, err := strconv.Atoi(lineRange[1])
	if err != nil {
		return nil, 0, 0, fmt.Errorf("invalid end line: %s; MUST be an integer", lineRange[1])
	}

	return parsedURI, start, end, nil
}
