package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
)

func main() {
	target := os.Getenv("TARGET")
	if target == "" {
		if _, err := fmt.Println("Error: TARGET environment variable is not set"); err != nil {
			log.Fatal(err.Error())
		}

		os.Exit(1)
	}

	metadataPath, exists := os.LookupEnv(component.SCANNER_TARGET_METADATA_PATH_ENV_VAR)
	if exists {
		if !strings.HasSuffix(metadataPath, "target.json") {
			metadataPath = filepath.Join(metadataPath, "target.json")
		}

		if err := overwriteMetadata(metadataPath, target); err != nil {
			if _, err := fmt.Println(errors.Errorf("could not write metadata: %w", err)); err != nil {
				log.Fatal(err.Error())
			}

			log.Fatal(err.Error())
		}
	}
}

func overwriteMetadata(metadataLocation string, target string) error {
	_, err := url.Parse(target)
	if err != nil {
		return errors.Errorf("could not parse target URL: %w", err)
	}

	dataSource := &ocsffindinginfo.DataSource{
		TargetType: ocsffindinginfo.DataSource_TARGET_TYPE_WEBSITE,
		WebsiteMetadata: &ocsffindinginfo.DataSource_WebsiteMetadata{
			Url: target,
		},
	}
	marshaledDataSource, err := protojson.Marshal(dataSource)
	if err != nil {
		return errors.Errorf("could not marshal data source into JSON: %w", err)
	}

	// Write content to the file
	err = os.WriteFile(metadataLocation, marshaledDataSource, 0644)
	if err != nil {
		return errors.Errorf("Error writing file: %w", err)
	}
	return nil
}
