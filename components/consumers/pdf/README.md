# PDF consumer

This consumer prints the pipeline results into a Go template, prints them into a
PDF and uploads them into an S3 bucket.

# How it works

The HTML template is in `/components/consumers/pdf/default.html` .\
The styles for it are inline.\
The PDF uses the Print styles, so it's slightly different from what you see in
the browser.
Then the component uses Playwright to render the template and print it into a
PDF.
The PDF is then uploaded into an S3 bucket.

# How to test locally

1. Install the requirements for the component. Check the Docker file (
   `/components/consumers/pdf/Dockerfile`) for the
   latest versions:

```
$ go install github.com/playwright-community/playwright-go/cmd/playwright@v0.4702.0
$ playwright install chromium --with-deps
```

2. Generate the PDF by running this in the `smithy` oss repo root. We don't want
   to upload to s3, so we add the `skips3`
   flag. The template file is in the component folder:

```
go run components/consumers/pdf/main.go 
-in components/consumers/pdf/example_data/gosec.enriched.aggregated.pb 
-skips3 -template="components/consumers/pdf/default.html"
```

This generates the PDF and the report.html in the root of your repo, without
uploading it to an S3 bucket. Don't forget
to delete it later.
