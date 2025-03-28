package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"

	"github.com/arangodb/go-driver"
	"github.com/arangodb/go-driver/http"

	"github.com/smithy-security/smithy/deprecated-components/consumers"
)

var (
	dbURL          string
	dbName         string
	collectionName string

	basicAuthUser string
	basicAuthPass string

	tlsInsecureSkipVerify bool
)

func init() {
	flag.StringVar(&dbURL, "db-url", "https://localhost:8529", "URL to connect to ArangoDB.")
	flag.StringVar(&dbName, "db-name", "smithy", "The ArangoDB database name to use.")
	flag.StringVar(&collectionName, "collection-name", "smithy", "The ArangoDB collection name to use.")
	flag.StringVar(&basicAuthUser, "basic-auth-user", "", "")
	flag.StringVar(&basicAuthPass, "basic-auth-pass", "", "")
	flag.BoolVar(&tlsInsecureSkipVerify, "tls-insecure-skip-verify", false, "Setting this skips verification of server TLS certificates.")
}

func main() {
	if err := consumers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	// Create an HTTP connection to the database
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if tlsInsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	conn, err := http.NewConnection(http.ConnectionConfig{
		Endpoints: []string{dbURL},
		TLSConfig: tlsConfig,
	})
	if err != nil {
		log.Fatalf("could not create HTTP connection: %s", err)
	}
	// Create a client
	c, err := driver.NewClient(driver.ClientConfig{
		Connection:     conn,
		Authentication: driver.BasicAuthentication(basicAuthUser, basicAuthPass),
	})
	if err != nil {
		log.Fatalf("could not create ArangoDB client: %s", err)
	}

	ctx := context.Background()

	// Open the DB for Smithy, creating it if it does not exist.
	db, err := getDatabase(ctx, c, dbName)
	if err != nil {
		log.Fatalf("could not get database: %s", err)
	}

	// Open a collection for Smithy, creating it if doest not exist.
	col, err := getCollection(ctx, db, collectionName)
	if err != nil {
		log.Fatalf("could not get collection: %s", err)
	}

	// Enumerate Smithy Issues to consume and create documents for each of them.
	if consumers.Raw {
		log.Println("Parsing Raw results")
		responses, err := consumers.LoadToolResponse()
		if err != nil {
			log.Fatal("could not load raw results, file malformed: ", err)
		}
		for _, res := range responses {
			// scanStartTime := res.GetScanInfo().GetScanStartTime().AsTime()
			for _, iss := range res.GetIssues() {
				log.Printf("Pushing %d, issues to es \n", len(responses))
				metadata, err := col.CreateDocument(ctx, iss)
				if err != nil {
					log.Fatalf("could not create document from '%#v': %s", iss, err)
				}
				log.Printf("created document: %s", metadata.Key)
			}
		}
	} else {
		log.Print("Parsing Enriched results")
		responses, err := consumers.LoadEnrichedToolResponse()
		if err != nil {
			log.Fatal("could not load enriched results, file malformed: ", err)
		}
		for _, res := range responses {
			// scanStartTime := res.GetOriginalResults().GetScanInfo().GetScanStartTime().AsTime()
			for _, iss := range res.GetIssues() {
				metadata, err := col.CreateDocument(ctx, iss)
				if err != nil {
					log.Fatalf("could not create document from '%#v': %s", iss, err)
				}
				log.Printf("created document: %s", metadata.Key)
			}
		}
	}
}

func getDatabase(ctx context.Context, c driver.Client, name string) (driver.Database, error) {
	exists, err := c.DatabaseExists(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("could not determine if database '%s' exists: %w", name, err)
	}

	if !exists {
		db, err := c.CreateDatabase(ctx, name, &driver.CreateDatabaseOptions{})
		if err != nil {
			return nil, fmt.Errorf("could not create database '%s': %w", name, err)
		}

		return db, nil
	}

	db, err := c.Database(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("could not get database '%s': %w", name, err)
	}

	return db, nil
}

func getCollection(ctx context.Context, db driver.Database, name string) (driver.Collection, error) {
	exists, err := db.CollectionExists(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("could not determine if collection '%s' exists: %w", name, err)
	}

	if !exists {
		col, err := db.CreateCollection(ctx, name, &driver.CreateCollectionOptions{
			Type:     driver.CollectionTypeDocument,
			IsSystem: false,
		})
		if err != nil {
			return nil, fmt.Errorf("could not create collection '%s': %w", name, err)
		}

		return col, nil
	}

	col, err := db.Collection(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("could not get collection '%s': %w", name, err)
	}

	return col, nil
}
