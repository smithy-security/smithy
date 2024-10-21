# Smithy Trivy Producer

This producer runs [aquasec/trivy](https://github.com/aquasecurity/trivy)
against the specified filesystem or image.
It then parses the results into the Smithy format and exits.

## Supported Commands

This producer has been tested with and currently supports the following trivy
commands:

* config
* filesystem
* image
* repository
* sbom

If you need support for more, please open a ticket or send a pull request.

## Supported Results Formats

Trivy-Producer currently supports the following output formats:

* json
* sarif
* cyclonedx-json

You can use this producer to scan an image for vulnerabilities or generate an
SBOM from both images and filesystems.
Accepted parameters and execution details can be found in
[task.yaml](./task.yaml)

## Testing without Smithy

You can run this producer outside of smithy for development with

```bash
go run ./components/producers/docker-trivy -in <trivy output> -format <what you passed as trivy -f flag> -out ./trivy.pb 
```

Trivy can be run as a docker image by pulling `aquasec/trivy`

## SBOM mode

If the format is `cyclonedx` the producer will output a `LaunchToolResponse`
containing a single issue which will have its `CycloneDXSBOM` field populated
with trivy's output.
