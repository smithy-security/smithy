package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/enrichers"

	"github.com/smithy-security/smithy/pkg/db"
	"github.com/smithy-security/smithy/pkg/enrichment"
)

var (
	connStr string
)

func main() {
	flag.StringVar(&connStr, "db_connection", enrichers.LookupEnvOrString("DB_CONNECTION", ""), "the database connection DSN")
	if err := enrichers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dbURL, err := db.ParseConnectionStr(connStr)
	if err != nil {
		return err
	}
	conn, err := dbURL.Connect()
	if err != nil {
		return err
	}
	res, err := enrichers.LoadData()
	if err != nil {
		return err
	}
	log.Printf("Loaded %d tagged tool responses\n", len(res))
	for _, r := range res {
		enrichedIssues := []*v1.EnrichedIssue{}
		log.Printf("enriching %d issues", len(r.GetIssues()))
		for _, i := range r.GetIssues() {
			eI, err := enrichment.EnrichIssue(conn, i)
			if err != nil {
				slog.Error(fmt.Sprintf("error enriching issue %s, err: %#v\n", i.Uuid, err))
				continue
			}
			enrichedIssues = append(enrichedIssues, eI)
			log.Printf("enriched issue '%s'", eI.GetRawIssue().GetUuid())
		}
		err := enrichers.WriteData(&v1.EnrichedLaunchToolResponse{
			OriginalResults: r,
			Issues:          enrichedIssues,
		}, "deduplication")
		if err != nil {
			return err
		}
	}
	return nil
}
