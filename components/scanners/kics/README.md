# KICS Scanner

## Overview

KICS (Keeping Infrastructure as Code Secure) is a static code analysis tool designed to detect security vulnerabilities, compliance issues, and misconfigurations in infrastructure-as-code (IaC) files. This component integrates KICS and parses its findings into the OCSF format.

## Version

This component uses KICS version `v2.1.13`.

## How to Run or Test

```bash
smithyctl workflow run  --build-component-images=true --overrides=./examples/kics/overrides.yaml ./examples/kics/workflow.yaml
```
