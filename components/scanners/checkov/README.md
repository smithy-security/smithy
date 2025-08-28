# Checkov Scanner

## Overview

Checkov is a static code analysis tool for infrastructure-as-code (IaC) to detect security and compliance misconfigurations. This component integrates Checkov and parses its findings into the OCSF format.

## Version

This component uses Checkov version `3.2.467`.

## How to Run

To run the Checkov scanner, follow these steps:

1. Ensure you have Docker installed and running on your system.

2. Execute the following command to run Checkov:

   ```bash
   docker run --rm \
     -v $(pwd):/src \
     bridgecrew/checkov:3.2.467 \
     -d=/src \
     -o=sarif \
     --output-file-path=/tmp/results_sarif.sarif \
     --soft-fail
   ```

3. The results will be saved in SARIF format at `/tmp/results_sarif.sarif`.

## How to Test

To test the Checkov scanner run the relevant example workflow.

```bash
smithyctl workflow run  --build-component-images=true --overrides=./examples/checkov/overrides.yaml ./examples/checkov/workflow.yaml
```
