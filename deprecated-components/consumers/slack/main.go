package main

import (
	"flag"
	"log"

	"github.com/smithy-security/smithy/deprecated-components/consumers/slack/utils"

	"github.com/smithy-security/smithy/deprecated-components/consumers"
)

var (
	// Webhook is the webhook url to post to.
	Webhook string
	// LongFormat : boolean, False by default, if set to True it dumps all findings in JSON format to the webhook url.
	LongFormat bool
	// Template is the template to be used when posting the results.
	// This consumer will replace 	// <numResults>, <scanID>, <scanStartTime> and <newResults> with the respective values.
	Template string
)

func main() {
	flag.StringVar(&Webhook, "webhook", "", "the Webhook to push results to")

	flag.StringVar(&Template, "template", "Smithy scan <scanID>, started at <scanStartTime>, completed with <numResults> out of which, <newResults> new", "the template to use when posting the results")
	flag.BoolVar(&LongFormat, "long", false, "post the full results to Webhook, not just metrics")

	if err := consumers.ParseFlags(); err != nil {
		log.Fatal("Could not parse flags:", err)
	}

	if Webhook == "" {
		log.Fatal("Webhook is undefined")
	}
	if consumers.Raw {
		responses, err := consumers.LoadToolResponse()
		if err != nil {
			log.Fatal("Could not load Raw tool response: ", err)
		}
		if LongFormat {
			messages, err := utils.ProcessRawMessages(responses)
			if err != nil {
				log.Fatal("Could not Process Raw Messages: ", err)
			}
			for _, msg := range messages {
				utils.PushMessage(msg, Webhook)
			}
		} else {
			scanInfo := utils.GetRawScanInfo(responses[0])
			msgNo := utils.CountRawMessages(responses)
			tstamp := scanInfo.GetScanStartTime().AsTime()
			utils.PushMetrics(scanInfo.GetScanUuid(), msgNo, tstamp, msgNo, Template, Webhook)
		}
	} else {
		responses, err := consumers.LoadEnrichedToolResponse()
		if err != nil {
			log.Fatal("Could not load Enriched tool response: ", err)
		}
		if LongFormat {
			messages, err := utils.ProcessEnrichedMessages(responses)
			if err != nil {
				log.Fatal("Could not Process Enriched messages: ", err)
			}
			for _, msg := range messages {
				utils.PushMessage(msg, Webhook)
			}
		} else {
			scanInfo := utils.GetEnrichedScanInfo(responses[0])
			msgNo := utils.CountEnrichedMessages(responses)
			newMsgs := utils.CountNewMessages(responses)
			tstamp := scanInfo.GetScanStartTime().AsTime()
			utils.PushMetrics(scanInfo.GetScanUuid(), msgNo, tstamp, newMsgs, Template, Webhook)
		}
	}
}
