package main

import (
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"slices"
	"strings"

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
			if res.RuleId == nil {
				continue
			}

			for _, loc := range res.Locations {
				if loc.PhysicalLocation == nil || loc.PhysicalLocation.ArtifactLocation == nil || loc.PhysicalLocation.ArtifactLocation.Uri == nil {
					continue
				}

				if _, exists := ids[*res.RuleId]; !exists {
					ids[*res.RuleId] = sets.Set[string]{}
				}

				ids[*res.RuleId].Insert(*loc.PhysicalLocation.ArtifactLocation.Uri)
			}
		}
	}

	return ids
}

type ruleDiffs struct {
	firstOnly    []string
	secondOnly   []string
	intersection []string
}

func (r ruleDiffs) String() (string, error) {
	sb := strings.Builder{}

	var errs error
	_, err := sb.WriteString("rule comparison report: \n")
	errs = errors.Join(errs, err)
	_, err = sb.WriteString("First Document Only: ")
	errs = errors.Join(errs, err)
	_, err = sb.WriteString(strings.Join(r.firstOnly, ", "))
	errs = errors.Join(errs, err)
	_, err = sb.WriteString("\nSecond Document Only: ")
	errs = errors.Join(errs, err)
	_, err = sb.WriteString(strings.Join(r.secondOnly, ", "))
	errs = errors.Join(errs, err)
	_, err = sb.WriteString("\nIntersection: ")
	errs = errors.Join(errs, err)
	_, err = sb.WriteString(strings.Join(r.intersection, ", "))
	errs = errors.Join(errs, err)
	_, err = sb.WriteString("\n==========================")
	errs = errors.Join(errs, err)

	return sb.String(), errs
}

type pathDiffs struct {
	firstOnly    map[string][]string
	secondOnly   map[string][]string
	intersection map[string][]string
}

func (p pathDiffs) String() (string, error) {
	sb := strings.Builder{}

	var errs error
	_, err := sb.WriteString("path comparison report: \n")
	errs = errors.Join(errs, err)
	_, err = sb.WriteString("First Document Only:")
	errs = errors.Join(errs, err)
	for ruleID, paths := range p.firstOnly {
		_, err = sb.WriteString(fmt.Sprintf("\n  RuleID - %s:\n  * ", ruleID))
		errs = errors.Join(errs, err)
		_, err = sb.WriteString(strings.Join(paths, "\n  * "))
		errs = errors.Join(errs, err)
	}

	_, err = sb.WriteString("\nSecond Document Only: ")
	errs = errors.Join(errs, err)
	for ruleID, paths := range p.secondOnly {
		_, err = sb.WriteString(fmt.Sprintf("\n  RuleID - %s:\n  * ", ruleID))
		errs = errors.Join(errs, err)
		_, err = sb.WriteString(strings.Join(paths, "\n  * "))
		errs = errors.Join(errs, err)
	}

	_, err = sb.WriteString("\nIntersection: ")
	errs = errors.Join(errs, err)
	for ruleID, paths := range p.intersection {
		_, err = sb.WriteString(fmt.Sprintf("\n  RuleID - %s:\n  * ", ruleID))
		errs = errors.Join(errs, err)
		_, err = sb.WriteString(strings.Join(paths, "\n  * "))
		errs = errors.Join(errs, err)
	}
	_, err = sb.WriteString("\n==========================")
	errs = errors.Join(errs, err)

	return sb.String(), errs
}

func compare(sarif1, sarif2 *sarifschemav210.SchemaJson) (ruleDiffs, pathDiffs) {
	ids1 := getFindingIDs(sarif1)
	ids2 := getFindingIDs(sarif2)

	idsSet1 := sets.New(slices.Collect(maps.Keys(ids1))...)
	idsSet2 := sets.New(slices.Collect(maps.Keys(ids2))...)

	result := ruleDiffs{
		firstOnly:    idsSet1.Difference(idsSet2).UnsortedList(),
		secondOnly:   idsSet2.Difference(idsSet1).UnsortedList(),
		intersection: idsSet1.Intersection(idsSet2).UnsortedList(),
	}

	paths := pathDiffs{
		firstOnly:    map[string][]string{},
		secondOnly:   map[string][]string{},
		intersection: map[string][]string{},
	}

	for id := range ids1 {
		if _, ok := ids2[id]; ok {
			intersection := ids1[id].Intersection(ids2[id]).UnsortedList()
			if len(intersection) > 0 {
				paths.intersection[id] = intersection
			}

			diffList := ids1[id].Difference(ids2[id]).UnsortedList()
			if len(diffList) > 0 {
				paths.firstOnly[id] = diffList
			}
		} else {
			paths.firstOnly[id] = ids1[id].UnsortedList()
		}
	}

	for id := range ids2 {
		if _, ok := ids1[id]; ok {
			diffList := ids2[id].Difference(ids1[id]).UnsortedList()
			if len(diffList) > 0 {
				paths.secondOnly[id] = diffList
			}
		} else {
			paths.secondOnly[id] = ids2[id].UnsortedList()
		}
	}

	return result, paths
}

func readSarif(path string) (sarif *sarifschemav210.SchemaJson, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Errorf("failed to open file %s: %w", path, err)
	}

	defer func() {
		err = errors.Join(err, f.Close())
	}()

	sarif = &sarifschemav210.SchemaJson{}
	if err := json.NewDecoder(f).Decode(sarif); err != nil {
		return nil, errors.Errorf("failed to decode SARIF file %s: %w", path, err)
	}

	return sarif, nil
}

func main() {
	sarifFile1 := flag.String("sarif1", "", "Path to first SARIF file")
	sarifFile2 := flag.String("sarif2", "", "Path to second SARIF file")
	flag.Parse()

	if *sarifFile1 == "" || *sarifFile2 == "" {
		log.Fatal("Both --sarif1 and --sarif2 flags must be provided")
	}

	if _, err := fmt.Println("comparing current sarif output with previous sarif output...\n=========================="); err != nil {
		log.Fatal(err.Error())
	}

	sarif1, err := readSarif(*sarifFile1)
	if err != nil {
		log.Fatal(err)
	}

	sarif2, err := readSarif(*sarifFile2)
	if err != nil {
		log.Fatal(err)
	}

	ruleDiffReport, pathDiffReport := compare(sarif1, sarif2)
	ruleDiffString, err := ruleDiffReport.String()
	if err != nil {
		log.Fatal(err.Error())
	}

	pathDiffString, err := pathDiffReport.String()
	if err != nil {
		log.Fatal(err.Error())
	}

	if _, err := fmt.Println(ruleDiffString, "\n", pathDiffString, "\n", "done!"); err != nil {
		log.Fatal(err.Error())
	}
}
