# Smithy CDXGEN Producer

This producer runs [CycloneDX/cdxgen](https://github.com/CycloneDX/cdxgen)
against the specified filesystem or image.
It then parses the results into the Smithy format and exits.

## Testing without Smithy

You can run this producer outside of smithy for development with

```bash
go run ./components/producers/cdxgen -in <any cyclonedx sbom document> -out ./cdxgen.pb 
```

cdxgen can be run as a docker image by pulling `ghcr.io/cyclonedx/cdxgen`

## SBOM mode

The producer will output a `LaunchToolResponse` containing a single issue which
will have its `CycloneDXSBOM` field populated with the output from cdxgen.
