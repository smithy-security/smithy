package main

import (
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"slices"

	"encoding/json"

	"github.com/go-errors/errors"
	sarifschemav210 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"k8s.io/apimachinery/pkg/util/sets"
)

func getFindingIDs(sarifDoc *sarifschemav210.SchemaJson) map[string]sets.Set[string] {
	ids := make(map[string]sets.Set[string])
	if sarifDoc == nil {
		return ids
	}
	for _, run := range sarifDoc.Runs {
		for _, res := range run.Results {
			if res.RuleId != nil {
				for _, loc := range res.Locations {
					if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil && loc.PhysicalLocation.ArtifactLocation.Uri != nil {
						if _, exists := ids[*res.RuleId]; !exists {
							ids[*res.RuleId] = sets.Set[string]{}
						}
						ids[*res.RuleId].Insert(*loc.PhysicalLocation.ArtifactLocation.Uri)
					}
				}
			}
		}
	}
	return ids
}
func compare(sarif1, sarif2 *sarifschemav210.SchemaJson) (map[string][]string, map[string]map[string][]string) {
	result := map[string][]string{
		"first-only":  {},
		"second-only": {},
		"both":        {},
	}

	ids1 := getFindingIDs(sarif1)
	ids2 := getFindingIDs(sarif2)

	idsSet1 := sets.Set[string]{}
	idsSet2 := sets.Set[string]{}
	idsSet1.Insert(slices.Collect(maps.Keys(ids1))...)
	idsSet2.Insert(slices.Collect(maps.Keys(ids2))...)
	result["both"] = idsSet1.Intersection(idsSet2).UnsortedList()
	result["first-only"] = idsSet1.Difference(idsSet2).UnsortedList()
	result["second-only"] = idsSet2.Difference(idsSet1).UnsortedList()

	paths := map[string]map[string][]string{
		"first-only":  {},
		"second-only": {},
		"both":        {},
	}

	for id := range ids1 {
		if _, ok := ids2[id]; ok {
			// Intersection of paths
			intersection := ids1[id].Intersection(ids2[id]).UnsortedList()
			if len(intersection) > 0 {
				paths["both"][id] = intersection
			}

			diffList := ids1[id].Difference(ids2[id]).UnsortedList()
			if len(diffList) > 0 {
				paths["first-only"][id] = diffList
			}
		} else {
			paths["first-only"][id] = ids1[id].UnsortedList()
		}
	}

	for id := range ids2 {
		if _, ok := ids1[id]; ok {
			diffList := ids2[id].Difference(ids1[id]).UnsortedList()
			if len(diffList) > 0 {
				paths["second-only"][id] = diffList
			}
		} else {
			paths["second-only"][id] = ids2[id].UnsortedList()
		}
	}

	// return both result and paths
	return result, paths
}

func readSarif(path string) (*sarifschemav210.SchemaJson, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Errorf("failed to open file %s: %w", path, err)
	}
	defer f.Close()
	var sarif sarifschemav210.SchemaJson
	if err := json.NewDecoder(f).Decode(&sarif); err != nil {
		return nil, errors.Errorf("failed to decode SARIF file %s: %w", path, err)
	}
	return &sarif, nil
}

func main() {
	sarifFile1 := flag.String("sarif1", "", "Path to first SARIF file")
	sarifFile2 := flag.String("sarif2", "", "Path to second SARIF file")
	flag.Parse()

	if *sarifFile1 == "" || *sarifFile2 == "" {
		log.Fatal("Both --sarif1 and --sarif2 flags must be provided")
	}

	fmt.Println("comparing current sarif output with previous sarif output...")
	fmt.Println("==========================")
	sarif1, err := readSarif(*sarifFile1)
	if err != nil {
		log.Fatal(err)
	}
	sarif2, err := readSarif(*sarifFile2)
	if err != nil {
		log.Fatal(err)
	}

	ruleDiffs, pathDiffs := compare(sarif1, sarif2)
	for k, v := range ruleDiffs {
		fmt.Println("comparison result", k, len(v))
		for _, item := range v {
			fmt.Println(" - ", item)
		}
		fmt.Println("==========================")
	}
	for k, v := range pathDiffs {
		fmt.Println("path comparison result", k)
		for ruleID, paths := range v {
			fmt.Printf(" RuleID: %s\n", ruleID)
			for _, p := range paths {
				fmt.Println("   - ", p)
			}
		}
		fmt.Println("==========================")
	}
	fmt.Println("done!")
}
