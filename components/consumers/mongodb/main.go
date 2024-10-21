package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/avast/retry-go/v4"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/smithy-security/smithy/components/consumers"
)

var (
	dbURL          string
	dbName         string
	collectionName string
)

func init() {
	flag.StringVar(&dbURL, "db-uri", "https://localhost:8529", "URI to connect to MongoDB.")
	flag.StringVar(&dbName, "db-name", "consumer-mongodb", "The MongoDB database name to use.")
	flag.StringVar(&collectionName, "collection-name", "consumer-mongodb", "The MongoDB collection name to use.")
}

func main() {
	if err := consumers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	if err := run(ctx); err != nil {
		log.Fatalf("could not run: %s", err)
	}
}

func run(ctx context.Context) error {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(dbURL))
	if err != nil {
		return err
	}

	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			log.Fatal(err)
		}
	}()

	coll := client.Database(dbName).Collection(collectionName)

	// Enumerate Smithy Issues to consume and create documents for each of them.
	if consumers.Raw {
		log.Println("Parsing Raw results")
		responses, err := consumers.LoadToolResponse()
		if err != nil {
			return fmt.Errorf("could not load raw results, file malformed: %w", err)
		}
		for _, res := range responses {
			// scanStartTime := res.GetScanInfo().GetScanStartTime().AsTime()
			for _, iss := range res.GetIssues() {
				if err := insertRetry(ctx, coll, iss); err != nil {
					return err
				}
			}
		}
	} else {
		log.Print("Parsing Enriched results")
		responses, err := consumers.LoadEnrichedToolResponse()
		if err != nil {
			return fmt.Errorf("could not load enriched results, file malformed: %w", err)
		}
		for _, res := range responses {
			// scanStartTime := res.GetOriginalResults().GetScanInfo().GetScanStartTime().AsTime()
			for _, iss := range res.GetIssues() {
				if err := insertRetry(ctx, coll, iss); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func insertRetry(ctx context.Context, coll *mongo.Collection, obj interface{}) error {
	return retry.Do(func() error {
		res, err := coll.InsertOne(ctx, obj)
		if err != nil {
			return fmt.Errorf("could not create document from '%#v': %w", obj, err)
		}
		log.Printf("created document: %s", res.InsertedID)
		return nil
	},
		retry.Attempts(10),
		retry.OnRetry(func(n uint, err error) {
			log.Printf("Retry creating document %d: %s", n, err)
		}),
	)
}
