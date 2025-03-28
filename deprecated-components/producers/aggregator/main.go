package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/putil"
)

var (
	readPath  string
	writePath string
)

func lookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func tagIssue(i *v1.Issue, scanUUUID string) *v1.Issue {
	id := uuid.New()
	i.Uuid = scanUUUID + ":" + id.String()
	return i
}

func run() {
	res, err := putil.LoadToolResponse(readPath)
	if err != nil {
		log.Fatalf("could not load tool response from path %s , error:%v", readPath, err)
	}
	for _, r := range res {
		taggedIssues := []*v1.Issue{}
		for _, i := range r.GetIssues() {
			eI := tagIssue(i, r.GetScanInfo().GetScanUuid())
			if err != nil {
				log.Println(err)
				continue
			}
			taggedIssues = append(taggedIssues, eI)
		}
		if err := putil.WriteResults(
			r.GetToolName(),
			taggedIssues,
			filepath.Join(writePath, fmt.Sprintf("%s.tagged.pb", r.GetToolName())),
			r.GetScanInfo().GetScanUuid(),
			r.GetScanInfo().GetScanStartTime().AsTime(),
			r.GetScanInfo().GetScanTags(),
		); err != nil {
			log.Fatalf("could not write results: %s", err)
		}
	}
}

func main() {
	flag.StringVar(&readPath, "read_path", lookupEnvOrString("READ_PATH", ""), "where to find producer results")
	flag.StringVar(&writePath, "write_path", lookupEnvOrString("WRITE_PATH", ""), "where to put tagged results")
	flag.Parse()
	run()
}
