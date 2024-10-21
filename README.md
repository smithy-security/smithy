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

By [Smithy](https://smithy.security/)
Security scanning,results unification and enrichment tool
([ASOC](https://www.gartner.com/reviews/market/application-security-orchestration-and-correlation-asoc-tools))

Security pipelines on Kubernetes. The purpose of this project is to provide a
scalable and flexible framework to execute arbitrary security scanning
tools on code and infrastructure while processing the results in a versatile
way.

```mermaid
flowchart LR
    S["Code Setup & Build"]

    P_GoSec["Producer - GoSec (Golang)"]
    P_SecBugs["Producer - SpotBugs (Java)"]
    P_Bandit["Producer - Bandit (Python)"]
    P_TFSec["Producer - TFSec (Terraform)"]

    P_Aggregator["Producer - Results Aggregation"]

    E_Deduplication["Enricher - Deduplication"]
    E_Policy["Enricher - Policy"]
    E_Aggregator["Enricher - Enriched Results Aggregator"]

    C_Slack["Consumer - Slack"]
    C_Elasticsearch["Consumer - Elasticsearch"]
    C_Jira["Consumer - Jira"]

    S-->P_TFSec
    S-->P_GoSec
    S-->P_SecBugs
    S-->P_Bandit

    P_TFSec-->P_Aggregator
    P_GoSec-->P_Aggregator
    P_SecBugs-->P_Aggregator
    P_Bandit-->P_Aggregator

    P_Aggregator-->E_Deduplication
    P_Aggregator-->E_Policy

    E_Policy-->E_Aggregator
    E_Deduplication-->E_Aggregator

    E_Aggregator-->C_Slack
    E_Aggregator-->C_Elasticsearch
    E_Aggregator-->C_Jira


```

## Getting Started

The [Getting Started](docs/getting-started.md) tutorial explains
how to get started with Smithy.
You can also access our community contributed pipelines
[here](https://github.com/smithy-security/smithy-community-pipelines).

## Announcements

This version of Smithy was announced at OWASP Appsec Dublin in 2023. Check out
[the slides](docs/presentations/Global_AppSecDublin_Presentation.pdf) and
[the video](https://www.youtube.com/watch?app=desktop\&list=PLpr-xdpM8wG8479ud_l4W93WU5MP2bg78\&v=i9j7n0WDBO0\&feature=youtu.be)
of the presentation.

## Support

If you have questions, reach out to us by opening a new
[issue](https://github.com/smithy-security/smithy/issues/new) on GitHub.

You can also get support on our [Discord server](https://discord.gg/xzsHxUxK).

## Development & Contributing

Contributions are welcome, see the [developing](docs/contributers/DEVELOPING.md)
and [releasing](docs/contributers/RELEASES.md) guides on how to get started.

## License

Smithy is under the Apache 2.0 license. See the [LICENSE](LICENSE) file for
details.
