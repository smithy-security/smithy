# Sobelow Scanner version v0.14.0

## Overview

Sobelow is a static analysis tool for discovering security vulnerabilities in Elixir web applications. It helps developers identify potential security issues in their code. This component integrates Sobelow and parses its findings into the OCSF format.

## Version

This component uses Sobelow v0.14.0

## How to Run

```bash
smithyctl workflow run  --build-component-images=true --overrides=./examples/sobelow/overrides.yaml ./examples/sobelow/workflow.yaml
```
