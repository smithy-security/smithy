package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/crypto/nacl/sign"

	"github.com/go-errors/errors"

	apiv1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components"
	"github.com/smithy-security/smithy/components/enrichers"
	"github.com/smithy-security/smithy/pkg/putil"
)

const signatureAnnotation = "JSON-Message-Signature"

var (
	readPath  string
	writePath string
	debug     bool
	signKey   string
	keyBytes  []byte
)

// Aggregation Rules:
// all k,v annotations get merged
// if there's a key conflict keep the value of the one you saw first.
func aggregateIssue(i *apiv1.EnrichedIssue, issues map[string]*apiv1.EnrichedIssue) map[string]*apiv1.EnrichedIssue {
	if _, ok := issues[i.RawIssue.Uuid]; ok { // do we already know about this Uuid?
		for k, v := range i.Annotations { // if yes, merge known Uuid annotations with new annotations
			if val, found := issues[i.RawIssue.Uuid].Annotations[k]; found {
				if val != v {
					log.Printf("The annotation %s exists both in  %#v and %#v and it doesn't have the same value, this is a bug!", k, i, issues[i.RawIssue.Uuid])
					continue
				}
			} else { // if new issue has an annotation that the old one doesn't already have
				if issues[i.RawIssue.Uuid].Annotations == nil {
					issues[i.RawIssue.Uuid].Annotations = make(map[string]string)
				}
				issues[i.RawIssue.Uuid].Annotations[k] = v
			}
		}
		// then merge all other fields

		// hash, count and firstseen are both used exclusively by the deduplication enricher they should be handled together
		if i.Count > issues[i.RawIssue.Uuid].Count {
			issues[i.RawIssue.Uuid].Count = i.Count

			if i.Hash != issues[i.RawIssue.Uuid].Hash {
				log.Println("issues", i.RawIssue.Title, "and", issues[i.RawIssue.Uuid].RawIssue.Title, "have the same uuid", i.RawIssue.Uuid, "but different hashes", i.Hash, "and", issues[i.RawIssue.Uuid].Hash, "this looks like a bug!")
				issues[i.RawIssue.Uuid].Hash = i.Hash
			}
			if i.FirstSeen != issues[i.RawIssue.Uuid].FirstSeen {
				issues[i.RawIssue.Uuid].FirstSeen = i.FirstSeen
			}
			if i.FalsePositive {
				issues[i.RawIssue.Uuid].FalsePositive = i.FalsePositive
			}
		}
	} else {
		log.Println("Logged new issue", i.RawIssue.Uuid)
		issues[i.RawIssue.Uuid] = i
	}
	return issues
}

// signMessage uses Nacl.Sign to append a Base64 encoded signature of the whole message to the annotation named: "JSON-Message-Signature".
func signMessage(i *apiv1.EnrichedIssue) (*apiv1.EnrichedIssue, error) {
	// if you have been instructed to sign results, then add the signature annotation
	log.Println("signing message " + i.RawIssue.Title)
	msg, err := json.Marshal(i)
	if err != nil {
		log.Printf("Error: could not serialise the message for signing")
		return &apiv1.EnrichedIssue{}, nil

	}
	if i.Annotations == nil {
		i.Annotations = make(map[string]string)
	}
	i.Annotations[signatureAnnotation] = base64.StdEncoding.EncodeToString(sign.Sign(nil, msg, (*[64]byte)(keyBytes)))
	return i, nil
}

func aggregateToolResponse(response *apiv1.EnrichedLaunchToolResponse, issues map[string]*apiv1.EnrichedIssue) map[string]*apiv1.EnrichedIssue {
	for _, i := range response.GetIssues() {
		issues = aggregateIssue(i, issues)
	}
	return issues
}

func run() error {
	results, err := putil.LoadEnrichedNonAggregatedToolResponse(readPath)
	if err != nil {
		return errors.Errorf("could not load tool response from path %s , error:%v", readPath, err)
	}

	if len(signKey) > 0 {
		keyBytes, err = base64.StdEncoding.DecodeString(signKey)
		if err != nil {
			return errors.Errorf("could not decode private key for signing")
		}
	}
	log.Printf("loaded %d, enriched but not aggregated tool responses\n", len(results))
	issues := make(map[string]map[string]*apiv1.EnrichedIssue)
	originalResponses := make(map[string]*apiv1.LaunchToolResponse)
	for _, r := range results {
		toolName := r.GetOriginalResults().GetToolName()
		originalResponses[toolName] = r.GetOriginalResults()
		if _, ok := issues[toolName]; !ok {
			issues[toolName] = make(map[string]*apiv1.EnrichedIssue)
		}
		issues[toolName] = aggregateToolResponse(r, issues[toolName])
	}

	for toolName, toolIssues := range issues {
		var result []*apiv1.EnrichedIssue
		for _, issue := range toolIssues {
			currentIssue := issue
			if len(signKey) > 0 {
				currentIssue, err = signMessage(currentIssue)
				if err != nil {
					log.Fatalf("could not sign message titled: %s", currentIssue.RawIssue.Title)
				}
			}
			result = append(result, currentIssue)
		}
		if err := putil.WriteEnrichedResults(originalResponses[toolName], result,
			filepath.Join(writePath, fmt.Sprintf("%s.enriched.aggregated.pb", toolName)),
		); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.StringVar(&readPath, "read_path", enrichers.LookupEnvOrString("READ_PATH", ""), "where to find producer results")
	flag.StringVar(&writePath, "write_path", enrichers.LookupEnvOrString("WRITE_PATH", ""), "where to put enriched results")
	flag.BoolVar(&debug, "debug", false, "turn on debug logging")
	flag.StringVar(&signKey, "signature_key", enrichers.LookupEnvOrString("B64_SIGNATURE_KEY", ""), "where to put tagged results")

	flag.Parse()
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})).With("scanID", os.Getenv(components.EnvSmithyScanID)))
	if readPath == "" {
		log.Fatal("read_path is undefined")
	}
	if writePath == "" {
		log.Fatal("write_path is undefined")
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
