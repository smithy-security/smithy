# OWASP Zaproxy producer

This producer runs owasp zaproxy using its
[automation framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/)
capabilities.
The producer takes the following arguments, in order of preference and ignores
the rest if multiples are provided:

* `producer-zaproxy-automation-framework-file-base64` : accepts a file generated
  by `zap.sh -cmd -autogenmin <file.yaml>` or
  `zap.sh -cmd -autogenmax <file.yaml>`, customized with the user's values and
  encoded in base64 format
* `producer-zaproxy-target` : accepts the target that will be passed to
  `zap.sh -quickurl`
* `producer-zaproxy-config-file-base64` : accept a base64 `config.xml` file from
  ZAP that will be passed to `zap.sh -configFile` be careful, zap configuration
  files can get very long and the base64 encoding of the file can exceed the
  Tekton variable limits. It is strongly advisable to limit the contents to only
  what you need.

## Automation Report section

For the producer to run, it is important that the report follows the template
`traditional-json` and it is written in `/zap/wrk/out.json` you can do so with
the following directives:

```yaml
  - type: report
    parameters:
      template: traditional-json
      reportDir: /zap/wrk
      reportFile: out.json

```

Every other part of the automation framework file is configurable.
