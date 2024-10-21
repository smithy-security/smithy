// Package main of the aws-s3 consumer implements a simple consumer for
// uploading smithy results to the S3 bucket passed as an argument
// the consumer expects the environment variables
// AWS_ACCESS_KEY_ID
// AWS_SECRET_ACCESS_KEY
// to be set
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"

	"github.com/smithy-security/smithy/components/consumers"
)

var (
	bucket string
	region string
)

func main() {
	flag.StringVar(&bucket, "bucket", "", "s3 bucket name")
	flag.StringVar(&region, "region", "", "s3 bucket region")
	if err := consumers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	if consumers.Raw {
		responses, err := consumers.LoadToolResponse()
		if err != nil {
			log.Fatal("could not load raw results, file malformed: ", err)
		}
		s3Data, err := json.Marshal(responses)
		if err != nil {
			log.Fatal("could not marshal results, err:", err)
		}
		filename := fmt.Sprintf("smithy scan %s-%s", responses[0].GetScanInfo().GetScanUuid(), responses[0].GetToolName())
		sendToS3(filename, bucket, region, s3Data)
	} else {
		responses, err := consumers.LoadEnrichedToolResponse()
		if err != nil {
			log.Fatal("could not load enriched results, file malformed: ", err)
		}
		filename := fmt.Sprintf("smithy scan %s-%s", responses[0].OriginalResults.GetScanInfo().GetScanUuid(), responses[0].OriginalResults.GetToolName())
		s3Data, err := json.Marshal(responses)
		if err != nil {
			log.Fatal("could not marshal results, err:", err)
		}
		sendToS3(filename, bucket, region, s3Data)
	}
}

func sendToS3(filename, bucket, region string, data []byte) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	},
	)
	if err != nil {
		log.Fatalf("Unable to acquire AWS session in region %s, check your credentials", region)
	}
	uploader := s3manager.NewUploader(sess)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(filename),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		log.Fatalf("Unable to upload %q to %q, %v", filename, bucket, err)
	}

	fmt.Printf("Successfully uploaded %q to %q\n", filename, bucket)
}
