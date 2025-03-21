# Smithy

[![Lint](https://github.com/smithy-security/smithy/actions/workflows/lint.yml/badge.svg)](https://github.com/smithy-security/smithy/actions/workflows/lint.yml)
[![Format](https://github.com/smithy-security/smithy/actions/workflows/format.yml/badge.svg)](https://github.com/smithy-security/smithy/actions/workflows/format.yml)
[![Test](https://github.com/smithy-security/smithy/actions/workflows/test.yml/badge.svg)](https://github.com/smithy-security/smithy/actions/workflows/test.yml)
[![Publish](https://github.com/smithy-security/smithy/actions/workflows/publish.yml/badge.svg)](https://github.com/smithy-security/smithy/actions/workflows/publish.yml)

<p align="center">
  <img alt="smithy-logo-dark-mode" src="assets/smithy-logo-light.svg#gh-dark-mode-only"/>
</p>
<p align="center">
  <img alt="smithy-logo-light-mode" src="assets/smithy-logo-dark.svg#gh-light-mode-only"/>
</p>

Smithy is a workflow engine for security tooling powered by [smithy.security](https://smithy.security/)
that automates security teams' frameworks built on top of [Open Cybersecurity Schema Framework](https://github.com/ocsf).

## Links

* [Architecture](./docs/architecture/README.md): understand how Smithy works
* [SDK](./sdk): build your custom security tooling on top of Smithy. [Example](https://github.com/smithy-security/smithy/pull/749).
* [Smithyctl](./smithyctl): CLI to build and execute workflows
* [Blog](https://smithy.security/blog/)
* Smithy at AppSecDublin: [slides](docs/presentations/Global_AppSecDublin_Presentation.pdf) and [video](https://www.youtube.com/watch?app=desktop\&list=PLpr-xdpM8wG8479ud_l4W93WU5MP2bg78\&v=i9j7n0WDBO0\&feature=youtu.be)
* Smithy at State Of Open Conf UK 2025: [slides](docs/presentations/SOOCon25.pdf) and [video](https://www.youtube.com/watch?v=SZR_Ll9dYWA)

## Getting Started

### Prerequisites

* [Go](https://go.dev/doc/install)
* [Docker](https://docs.docker.com/engine/install/)
* Install Smithy with `go install github.com/smithy-security/smithy/smithyctl@latest`

### Execute a workflow

Clone this repository `git clone https://github.com/smithy-security/smithy.git` and run the
following command from within it:

```shell
smithyctl workflow run --spec-path=examples/golang/workflow.yaml --build-component-images=true
```

Check the findings in the logs.

## Developing and publishing a component

Please check the docs over [here](./docs/developing-components/README.md)

## Contacts

Join our [Discord server](https://discord.gg/xzsHxUxK) to get support and ask questions.
