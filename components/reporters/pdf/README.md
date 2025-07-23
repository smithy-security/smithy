# PDF

This component implements
a [reporter](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that prints vulnerability findings into a PDF and uploads it to an AWS
S3 bucket.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined
[here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component)
as the following:

| Environment Variable  | Type   | Required | Default | Description                                                          |
|-----------------------|--------|----------|---------|----------------------------------------------------------------------|
| AWS\_ACCESS\_KEY\_ID     | string | yes      | -       | Your S3 access key ID for a user that has write access to the bucket |
| AWS\_SECRET\_ACCESS\_KEY | string | yes      | -       | Your S3 access key for a user that has write access to the bucket    |
| BUCKET\_NAME           | string | yes      | -       | Your S3 bucket name, e.g. "test-bucket"                              |
| BUCKET\_REGION         | string | yes      | -       | Your S3 bucket region, e.g. "us-west-1"                              |

On AWS, you will need a new IAM user with programmatic access and
with write permissions for your S3 bucket.

## Using with local S3 implementations

To use this component with local S3 implementations (like LocalStack or S3-ninja), you need to set the `BUCKET_ENDPOINT` environment variable to point to your local S3 endpoint. For example:

```bash
export BUCKET_ENDPOINT=http://<you ip>:4566
```

This will configure the S3 client to use the specified endpoint instead of the default AWS endpoint.

You may also need to set the `BUCKET_REGION` to a valid region string, even if your local S3 implementation does not use regions.

When using a custom endpoint, the component will automatically switch to path-style addressing instead of subdomain-style addressing, which is often required by local S3 implementations.

## Testing with s3-ninja

Run s3-ninja:

```bash
docker run -p 9444:9000 scireum/s3-ninja:latest
```

Create a bucket named test:

```bash
curl http://localhost:9444/ui/test\?create
```

Grab the key and secret from the UI at http://localhost:9444/ui

Run the component with a workflow that uses the PDF reporter, and set the following environment variables:

```bash
# overrides.yaml
git-clone:
- name: "repo_url"
  type: "string"
  value: "https://github.com/0c34/govwa.git"
- name: "reference"
  type: "string"
  value: "master"
pdf:
- name: "bucket_endpoint"
  type: "string"
  value: "<your local s3-ninja endpoint, e.g. http://<your-ip>:9444>"
- name: "bucket_name"
  type: "string"
  value: "test"
- name: aws_access_key_id
  type: "string"
  value: "<your access key>"
- name: aws_secret_access_key
  type: "string"
  value: "<your secret key>"
```

```bash
# workflow.yaml
description: PDF Reporter workflow
name: pdf
components:
- component: file://components/targets/git-clone/component.yaml
- component: file://components/scanners/gosec/component.yaml
- component: file://components/scanners/nancy/component.yaml
- component: file://components/enrichers/custom-annotation/component.yaml
- component: file://components/reporters/pdf/component.yaml
```

You should be able to see the uploaded file in the s3-ninja UI at http://localhost:9444/ui/test
