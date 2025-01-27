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

## How to run

Execute:

```shell
docker-compose up --build --force-recreate --remove-orphans
```

Then shutdown with:

```shell
docker-compose down --rmi all
```
