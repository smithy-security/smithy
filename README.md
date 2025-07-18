# Smithy

[![Lint](https://github.com/smithy-security/smithy/actions/workflows/lint.yml/badge.svg)](https://github.com/smithy-security/smithy/actions/workflows/lint.yml)
[![Format](https://github.com/smithy-security/smithy/actions/workflows/format.yml/badge.svg)](https://github.com/smithy-security/smithy/actions/workflows/format.yml)

[![Test Go](https://github.com/smithy-security/smithy/actions/workflows/test-go.yml/badge.svg)](https://github.com/smithy-security/smithy/actions/workflows/test-go.yml)

[![Test Python](https://github.com/smithy-security/smithy/actions/workflows/test-py.yml/badge.svg)](https://github.com/smithy-security/smithy/actions/workflows/test-py.yml)

[![Build component image and package](https://github.com/smithy-security/smithy/actions/workflows/package-component.yaml/badge.svg)](https://github.com/smithy-security/smithy/actions/workflows/package-component.yaml)

<p align="center">
  <img alt="smithy-logo-dark-mode" src="assets/smithy-logo-light.svg#gh-dark-mode-only"/>
</p>
<p align="center">
  <img alt="smithy-logo-light-mode" src="assets/smithy-logo-dark.svg#gh-light-mode-only"/>
</p>

# Smithy: The AppSec Workflow Engine

Smithy is a framework for building, automating, and standardizing security workflows, without drowning in dashboards or duct, taped scripts.

## Why Smithy?

Security teams today juggle dozens of tools. Each is great at one thing, but none built to work together. Smithy solves this by letting you:

* **Define workflows as code**
* **Integrate any tool** with a simple [SDK](./sdk)
* **Normalize outputs** into [OCSF](https://ocsf.io/) for consistent reporting
* **Automate triaging, reporting or remedial actions** with reusable, testable components
* **Validate security controls** for DevSecOps and GRC programs
* **Use or contribute open workflows** built by the community

Whether you're managing cloud gremlins, AppSec scanners, compliance checks or evidence gathering, Smithy helps teams automate what matters—**without building brittle glue code**, because your bash scripts hate you.

## What It Looks Like

```yaml
# Example: Run SAST, SCA, Secrets and IAC scanning
name: basic-devsecops
description: do the devsecops thing, look mum, i'm shifting left
components: 
- component: ghcr.io/smithy-security/smithy/manifests/components/targets/git-clone:v1.4.0
- component: ghcr.io/smithy-security/smithy/manifests/components/scanners/osv-scanner:v1.2.3
- component: ghcr.io/smithy-security/smithy/manifests/components/scanners/checkov:v1.1.1
- component: ghcr.io/smithy-security/smithy/manifests/components/scanners/semgrep:v1.3.2
- component: ghcr.io/smithy-security/smithy/manifests/components/scanners/trufflehog:v1.2.2
- component: ghcr.io/smithy-security/smithy/manifests/components/enrichers/custom-annotation:v0.2.1
- component: ghcr.io/smithy-security/smithy/manifests/components/reporters/vulnerability-logger:v0.0.1
```

## Quickstart

### Prerequisites

* [Go](https://go.dev/doc/install)
* [Docker](https://docs.docker.com/engine/install/)
* Install Smithy with `go install github.com/smithy-security/smithy/smithyctl@latest`

### Execute a workflow

Create the following files with the following contents:

```yaml
# workflow.yaml
name: basic-devsecops
description: do the devsecops thing, look mum, I'm shifting left
components:
- component: ghcr.io/smithy-security/smithy/manifests/components/targets/git-clone:v1.4.0
- component: ghcr.io/smithy-security/smithy/manifests/components/scanners/semgrep:v1.3.2
- component: ghcr.io/smithy-security/smithy/manifests/components/enrichers/custom-annotation:v0.2.1
- component: ghcr.io/smithy-security/smithy/manifests/components/reporters/vulnerability-logger:v0.0.1
```

```yaml
git-clone:
- name: "repo_url"
  type: "string"
  value: "https://github.com/smithy-security/e2e-monorepo.git"
```

Then run the following command to run your workflow

```shell
smithyctl workflow run --overrides=./overrides.yaml ./workflow.yaml
```

Check the findings in the logs.

## Stay in the Loop

We’re building Smithy in the open and we’d love to keep you updated.

Subscribe to the **Smithy newsletter** for:

* New workflow and component drops
* Release announcements
* Upcoming talks and workshops (BSides, DEFCON, OWASP, etc.)
* Tips on building smarter security workflows

[Sign up here](https://smithy.security/#newsletter) it’s low-volume, high-signal.

## Developing and publishing a component

Please check the [docs](./docs/developing-components/README.md)

## Contacts, Community and Support

Join our [Discord server](https://discord.gg/kuNnnVq9) to get support and ask questions.

## Links

* [Architecture](./docs/architecture/README.md): understand how Smithy works
* [SDK](./sdk): build your custom security tooling on top of Smithy. [Example](https://github.com/smithy-security/smithy/pull/749).
* [Smithyctl](./smithyctl): CLI to build and execute workflows
* [Blog](https://smithy.security/blog/)
* [Website](https://smithy.security)
