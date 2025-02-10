package putil

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"google.golang.org/protobuf/proto"
)

// LoadToolResponse loads raw results.
func LoadToolResponse(inPath string) ([]*v1.LaunchToolResponse, error) {
	responses := []*v1.LaunchToolResponse{}
	if err := filepath.Walk(inPath, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return fmt.Errorf("path %s doesn't exist", path)
		}
		if !f.IsDir() && (strings.HasSuffix(f.Name(), ".pb")) {
			pbBytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			res := v1.LaunchToolResponse{}
			if err := proto.Unmarshal(pbBytes, &res); err != nil {
				log.Printf("skipping %s as unable to unmarshal", path)
			} else {
				responses = append(responses, &res)
			}
		}
		return nil
	}); err != nil {
		return responses, err
	}
	return responses, nil
}

// LoadTaggedToolResponse loads raw results that have been tagged, it's used by the enrichers.
func LoadTaggedToolResponse(inPath string) ([]*v1.LaunchToolResponse, error) {
	responses := []*v1.LaunchToolResponse{}
	if err := filepath.Walk(inPath, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return fmt.Errorf("path %s doesn't exist", path)
		}
		if !f.IsDir() && (strings.HasSuffix(f.Name(), ".tagged.pb")) {
			pbBytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			res := v1.LaunchToolResponse{}
			if err := proto.Unmarshal(pbBytes, &res); err != nil {
				log.Printf("skipping %s as unable to unmarshal", path)
			} else {
				responses = append(responses, &res)
			}
		}
		return nil
	}); err != nil {
		return responses, err
	}
	return responses, nil
}

// LoadEnrichedToolResponse loads enriched results from the enricher.
func LoadEnrichedToolResponse(inPath string) ([]*v1.EnrichedLaunchToolResponse, error) {
	responses := []*v1.EnrichedLaunchToolResponse{}
	if err := filepath.Walk(inPath, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return fmt.Errorf("path %s doesn't exist", path)
		}
		if !f.IsDir() && (strings.HasSuffix(f.Name(), ".enriched.aggregated.pb")) {
			pbBytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			res := v1.EnrichedLaunchToolResponse{}
			if err := proto.Unmarshal(pbBytes, &res); err != nil {
				log.Printf("skipping %s as unable to unmarshal", path)
			} else {
				responses = append(responses, &res)
			}
		}
		return nil
	}); err != nil {
		return responses, err
	}
	return responses, nil
}

// LoadEnrichedNonAggregatedToolResponse loads enriched but not aggregated results from the enricher.
func LoadEnrichedNonAggregatedToolResponse(inPath string) ([]*v1.EnrichedLaunchToolResponse, error) {
	responses := []*v1.EnrichedLaunchToolResponse{}
	if err := filepath.Walk(inPath, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return fmt.Errorf("path %s doesn't exist", path)
		}
		if !f.IsDir() && (strings.HasSuffix(f.Name(), ".enriched.pb")) {
			pbBytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			res := v1.EnrichedLaunchToolResponse{}
			if err := proto.Unmarshal(pbBytes, &res); err != nil {
				log.Printf("skipping %s as unable to unmarshal", path)
			} else {
				responses = append(responses, &res)
			}
		}
		return nil
	}); err != nil {
		return responses, err
	}
	return responses, nil
}
