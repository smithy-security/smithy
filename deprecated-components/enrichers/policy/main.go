package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strconv"

	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/enrichers"
	opaclient "github.com/smithy-security/smithy/deprecated-components/enrichers/policy/opaClient"
)

var (
	policy     string
	regoServer string
	annotation string
)

const defaultAnnotation = "Policy Pass: "

type opaIssue struct {
	Input map[string]interface{}
}

func enrichIssue(i *v1.Issue, client opaclient.Client) (*v1.EnrichedIssue, error) {
	var strFinding map[string]interface{}

	if err := json.Unmarshal([]byte(protojson.Format(i)), &strFinding); err != nil {
		log.Println("Could not marshal proto to json err:", err)
	}
	opaIssue := opaIssue{
		Input: strFinding,
	}
	marshalled, err := json.Marshal(opaIssue)
	if err != nil {
		log.Printf("Could not marshal issue err is: %v", err)
	}
	passed, err := client.Decide(marshalled)
	if err != nil {
		log.Printf("Could not make a decision on finding %v, returning false, err is: %v", i, err)
	}
	issue := &v1.EnrichedIssue{
		RawIssue:    i,
		Annotations: map[string]string{},
	}
	issue.Annotations[annotation+client.PolicyPath] = strconv.FormatBool(passed)
	log.Printf("Evaluated %s to %t on issue titled %s", client.PolicyPath, passed, i.Title)
	return issue, nil
}

func run() error {
	res, err := enrichers.LoadData()
	if err != nil {
		return err
	}
	if annotation == "" {
		annotation = defaultAnnotation
	}
	client := opaclient.Client{
		RemoteURI: regoServer,
		Policy:    policy,
	}
	if err := client.Bootstrap(); err != nil {
		return fmt.Errorf("could not bootstrap OPA policies, err: %v", err)
	}
	log.Printf("successfully bootstrapped policy %s", client.PolicyPath)
	for _, r := range res {
		enrichedIssues := []*v1.EnrichedIssue{}
		for _, i := range r.GetIssues() {
			eI, err := enrichIssue(i, client)
			if err != nil {
				log.Println(err)
				continue
			}
			enrichedIssues = append(enrichedIssues, eI)
		}

		err := enrichers.WriteData(&v1.EnrichedLaunchToolResponse{
			OriginalResults: r,
			Issues:          enrichedIssues,
		}, "policy")
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.StringVar(&policy, "policy", enrichers.LookupEnvOrString("POLICY", ""), "base64 encoded policy")
	flag.StringVar(&annotation, "annotation", enrichers.LookupEnvOrString("ANNOTATION", defaultAnnotation), "How to label the issues this binary will enrich by default `Policy Pass: <name of the policy>`")
	flag.StringVar(&regoServer, "opa_server", enrichers.LookupEnvOrString("OPA_SERVER", "http://127.0.0.1:8181"), "where to find the rego server")
	if err := enrichers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
