# client-go

[![CI](https://github.com/DependencyTrack/client-go/actions/workflows/ci.yml/badge.svg)](https://github.com/DependencyTrack/client-go/actions/workflows/ci.yml)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/DependencyTrack/client-go)](https://pkg.go.dev/github.com/DependencyTrack/client-go)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](LICENSE)

*Go client library for [OWASP Dependency-Track](https://dependencytrack.org/)*

## Introduction

*client-go* is a Go library to interact with Dependency-Track's REST API, making it easy to implement
custom automation around Dependency-Track.

Example use-cases include:

* Interacting with Dependency-Track in CI/CD pipelines
  * e.g. to implement quality gates, or generate build reports
* Uploading BOMs of various origins
  * e.g. from all containers running in a Kubernetes cluster, see [sbom-operator](https://github.com/ckotzbauer/sbom-operator)
* Reacting to Webhook notifications
  * e.g. to automate analysis decisions on findings, see [dtapac](https://github.com/nscuro/dtapac)
* Reporting and tracking of portfolio metrics in specialized systems
  * e.g. to expose metrics to time-series databases like Prometheus, see [dependency-track-exporter](https://github.com/jetstack/dependency-track-exporter)

## Installation

```
go get github.com/DependencyTrack/client-go
```

## Compatibility

| *client-go* Version | Go Version | Dependency-Track Version |
| :-----------------: | :--------: | :----------------------: |
|       v0.8.0        |   1.18+    |          4.0.0+          |
|       v0.9.0+       |   1.19+    |          4.0.0+          |

## Usage

Please refer to the [documentation](https://pkg.go.dev/github.com/DependencyTrack/client-go).

## API Coverage

*client-go* primarily covers those parts of the Dependency-Track API that the community has an explicit need for.
If you'd like to use this library, and your desired functionality is not yet available, please consider creating a PR.
