package utils

import (
	"log"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/consumers"
	"github.com/smithy-security/smithy/pkg/jira/document"
)

// ProcessMessages processess all the v1.LaunchToolResponses (or v1.EnrichedToolResponses if consumers.Raw is false) and returns:
// :return messages - a list of HashMaps containing all the parsed smithy issues that are equal & above the specified severity threshold
// :return discardedMsgs - the number of messages that have been discarded by the allowDuplicates or allowFP policies
// :return error - if there is any error throughout the processing.
func ProcessMessages(allowDuplicates, allowFP bool, sevThreshold int) ([]document.Document, int, error) {
	if consumers.Raw {
		log.Print("Parsing Raw results")
		responses, err := consumers.LoadToolResponse()
		if err != nil {
			log.Print("Could not load Raw tool response: ", err)
			return nil, 0, err
		}
		messages, discarded := ProcessRawMessages(responses, sevThreshold)
		return messages, discarded, nil
	}
	log.Print("Parsing Enriched results")
	responses, err := consumers.LoadEnrichedToolResponse()
	if err != nil {
		log.Print("Could not load Enriched tool response: ", err)
		return nil, 0, err
	}
	messages, discarded := ProcessEnrichedMessages(responses, allowDuplicates, allowFP, sevThreshold)
	return messages, discarded, nil
}

// ProcessRawMessages returns a list of HashMaps of the v1.LaunchToolResponses.
func ProcessRawMessages(responses []*v1.LaunchToolResponse, sevThreshold int) ([]document.Document, int) {
	var messages []document.Document
	for _, res := range responses {
		scanStartTime := GetRawScanInfo(res).GetScanStartTime().AsTime()
		for _, iss := range res.GetIssues() {
			// Discard issues that don't pass the severity threshold
			if iss.GetSeverity() < v1.Severity(sevThreshold) {
				continue
			}
			doc := document.NewRaw(scanStartTime, res, iss)
			messages = append(messages, doc)
		}
	}
	return messages, 0
}

// ProcessEnrichedMessages returns a list of HashMaps of the v1.EnrichedLaunchToolResponses.
func ProcessEnrichedMessages(responses []*v1.EnrichedLaunchToolResponse, allowDuplicate, allowFP bool, sevThreshold int) ([]document.Document, int) {
	discardedMsgs := 0
	var messages []document.Document
	for _, res := range responses {
		scanStartTime := GetEnrichedScanInfo(res).GetScanStartTime().AsTime()
		for _, iss := range res.GetIssues() {
			// Discard issues that don't pass the severity threshold
			if iss.GetRawIssue().GetSeverity() < v1.Severity(sevThreshold) {
				continue
				// Discard issues that are duplicates or false positives, according to the policy
			}
			if (!allowDuplicate && iss.GetCount() > 1) || (!allowFP && iss.GetFalsePositive()) {
				discardedMsgs++
				continue
			} else {
				log.Println("Issue ", iss.GetRawIssue().GetTitle(), "is new", "target", iss.GetRawIssue().GetTarget(), "count", iss.GetCount())
			}
			doc := document.NewEnriched(scanStartTime, res, iss)
			messages = append(messages, doc)
		}
	}
	return messages, discardedMsgs
}

// GetRawScanInfo returns the non-enriched response's scan info.
func GetRawScanInfo(response *v1.LaunchToolResponse) *v1.ScanInfo {
	return response.GetScanInfo()
}

// GetEnrichedScanInfo returns the enriched response's scan info.
func GetEnrichedScanInfo(response *v1.EnrichedLaunchToolResponse) *v1.ScanInfo {
	return response.GetOriginalResults().GetScanInfo()
}
