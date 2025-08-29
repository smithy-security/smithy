# source-code-artifact

This component implements a [target](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go) that downloads and extracts archived source code from various sources including HTTP endpoints and S3-compatible storage.

The component supports `.zip`, `.tar`,`.apk` and `.tar.gz` archive formats from multiple protocols and automatically extracts the contents for analysis by downstream components.

## Supported Sources

The component can download archives from:

**HTTP/HTTPS URLs:**

```
https://github.com/example/repo/archive/refs/heads/main.zip
```

**S3-compatible URLs:**

```
s3://my-bucket/my-archive.tar
gs://my-bucket/my-archive.tar.gz
```

## Configuration

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `artifact_url` | URL to the archive file | `https://github.com/0c34/govwa/archive/refs/heads/master.zip` |
| `artifact_reference` | Branch, tag, or reference identifier | `main`, `v1.2.3`, `feature-branch` |

### Optional Parameters

| Parameter                       | Type | Default | Description                            |
|---------------------------------|------|---------|----------------------------------------|
| `artifact_registry_region`      | string | "" | AWS region for S3-compatible endpoints |
| `artifact_registry_auth_id`     | string | "" | Auth ID for authentication             |
| `artifact_registry_auth_secret` | string | "" | Secret for authentication              |

**Note:**

* For S3, `artifact_registry_auth_id` and `artifact_registry_auth_secret` are used as Access Key ID and Access Key secret.
* For HTTP endpoints, `artifact_registry_auth_id` and `artifact_registry_auth_secret` are used as username and password for basic authentication.

## Supported Archive Formats

* **ZIP**: `.zip` files
* **APK**: `.apk` files
* **TAR**: `.tar` files
* **TAR.GZ**: `.tar.gz` and `.tgz` files

## Environment Variables

The component uses environment variables for configuration. It requires the component environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well as the ones defined in the [component.yaml](./component.yaml).
