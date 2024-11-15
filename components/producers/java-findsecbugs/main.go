package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"github.com/smithy-security/smithy/components/producers"
	"github.com/smithy-security/smithy/pkg/sarif"
)

type jar struct {
	XMLName xml.Name `xml:"Jar"`
}

type project struct {
	XMLName xml.Name `xml:"Project"`
	Jar     *jar     `xml:"Jar"`
}

type method struct {
	XMLName    xml.Name     `xml:"Method"`
	Classname  string       `xml:"classname,attr"`
	Name       string       `xml:"name,attr"`
	Signature  string       `xml:"signature,attr"`
	IsStatic   string       `xml:"isStatic,attr"`
	SourceLine []sourceLine `xml:"SourceLine"`
}
type sourceLine struct {
	XMLName       xml.Name `xml:"SourceLine"`
	Classname     string   `xml:"classname,attr"`
	Start         string   `xml:"start,attr"`
	End           string   `xml:"end,attr"`
	StartBytecode string   `xml:"startBytecode,attr"`
	EndBytecode   string   `xml:"endBytecode,attr"`
	Sourcefile    string   `xml:"sourcefile,attr"`
	Sourcepath    string   `xml:"sourcepath,attr"`
	Role          string   `xml:"role,attr"`
}
type class struct {
	XMLName    xml.Name     `xml:"Class"`
	Classname  string       `xml:"classname,attr"`
	Role       string       `xml:"role,attr"`
	SourceLine []sourceLine `xml:"SourceLine"`
}
type field struct {
	XMLName    xml.Name     `xml:"Field"`
	Classname  string       `xml:"classname,attr"`
	SourceLine []sourceLine `xml:"SourceLine"`
}
type bugInstance struct {
	XMLName      xml.Name     `xml:"BugInstance"`
	Class        []class      `xml:"Class"`
	Method       []method     `xml:"Method"`
	SourceLine   []sourceLine `xml:"SourceLine"`
	Field        []field      `xml:"Field"`
	LongMessage  string       `xml:"LongMessage"`
	ShortMessage string       `xml:"ShortMessage"`
	Type         string       `xml:"type,attr"`
	Priority     string       `xml:"priority,attr"`
	Rank         string       `xml:"rank,attr"`
	Abbrev       string       `xml:"abbrev,attr"`
	Category     string       `xml:"category,attr"`
}
type bugCollection struct {
	XMLName     xml.Name      `xml:"BugCollection"`
	Project     *project      `xml:"Project"`
	BugInstance []bugInstance `xml:"BugInstance"`
}

func loadXML(filename string) ([]byte, error) {
	xmlFile, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer xmlFile.Close()
	return io.ReadAll(xmlFile)
}

func readXML(xmlFile []byte) []*v1.Issue {
	/**
	Reads a file containing spotbugs XML results
	and converts the results in the "SECURITY" category
	into an array Smithy issues
	*/

	output := []*v1.Issue{}
	var bugs bugCollection
	if len(xmlFile) == 0 {
		return output
	}
	err := xml.Unmarshal(xmlFile, &bugs)
	if err != nil {
		log.Fatal("could not unmarshal findsecbugs output", err)
	}
	for _, instance := range bugs.BugInstance {

		// parse standalone SourceLine elements
		for _, line := range instance.SourceLine {
			output = append(output, parseLine(instance, line))
		}
		// parse SourceLines in Field elements
		for _, field := range instance.Field {
			for _, line := range field.SourceLine {
				output = append(output, parseLine(instance, line))
			}
		}
		// parse SourceLines in Method elements
		for _, method := range instance.Method {
			for _, line := range method.SourceLine {
				output = append(output, parseLine(instance, line))
			}
		}
		// parse SourceLines in Class elements
		for _, cls := range instance.Class {
			for _, line := range cls.SourceLine {
				output = append(output, parseLine(instance, line))
			}
		}

	}
	return output
}

func parseLine(instance bugInstance, sourceLine sourceLine) *v1.Issue {
	return &v1.Issue{
		Target:      fmt.Sprintf("%s:%s-%s", sourceLine.Sourcepath, sourceLine.Start, sourceLine.End),
		Type:        instance.Type,
		Severity:    normalizeRank(instance.Rank),
		Cvss:        0.0,
		Confidence:  v1.Confidence(v1.Confidence_value[fmt.Sprintf("CONFIDENCE_%s", "MEDIUM")]),
		Description: instance.LongMessage,
		Title:       instance.ShortMessage,
	}
}

func normalizeRank(rank string) v1.Severity {
	/*
			Normalizes the rank according to the following table
			Scariest: ranked between 1 & 4.
		Scary: ranked between 5 & 9.
		Troubling: ranked between 10 & 14.
		Of concern: ranked between 15 & 20.
	*/
	intRank, err := strconv.ParseInt(rank, 10, 64)
	if err != nil {
		fmt.Println(err)
	}
	switch {
	case 1 < intRank && intRank < 4:
		return v1.Severity_SEVERITY_CRITICAL
	case 5 < intRank && intRank < 9:
		return v1.Severity_SEVERITY_HIGH
	case 10 < intRank && intRank < 14:
		return v1.Severity_SEVERITY_MEDIUM
	case 15 < intRank && intRank < 20:
		return v1.Severity_SEVERITY_LOW
	}
	return v1.Severity_SEVERITY_INFO
}

// Sarif is the switch that tells us that findsecbugs output is in sarif format.
var Sarif bool

func main() {
	flag.BoolVar(&Sarif, "sarifOut", false, "Output is in sarif format}")

	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	issues := []*v1.Issue{}
	if Sarif {
		var sarifResults []*sarif.SmithyIssueCollection
		inFile, err := producers.ReadInFile()
		if err != nil {
			log.Fatal(err)
		}
		sarifResults, err = sarif.ToSmithy(string(inFile), sarif.ExtraContextLanguageUnspecified)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(len(sarifResults))
		for _, result := range sarifResults {
			if result.ToolName != "SpotBugs" {
				log.Printf("Toolname from Sarif results is not 'SpotBugs' it is %s instead\n", result.ToolName)
			}
			issues = append(issues, result.Issues...)
		}
	} else {
		xmlByteVal, _ := loadXML(producers.InResults)
		issues = readXML(xmlByteVal)
	}
	if err := producers.WriteSmithyOut(
		"spotbugs",
		issues,
	); err != nil {
		log.Fatal(err)
	}
}
