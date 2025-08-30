# Zap Authenticated Scan Orchestration

This directory contains the orchestration logic and configuration for running ZAP (Zed Attack Proxy) authenticated scans as part of a Smithy workflow. It includes a Python script (`zap-authenticated-scan.py`) that enables flexible, automated, and authenticated web application scanning.

## Overview

The ZAP authenticated scan component launches a ZAP daemon, configures scan parameters, sets up authentication, and runs both spidering and active scanning against a target web application. Results are output in SARIF format for downstream processing.

## Parameters and Their Impact

All parameters are defined in `component.yaml` and passed to the Python orchestration script. Below is a detailed explanation of each parameter and its effect on scan behavior:

### Authentication Parameters

* **login\_url**: The URL to the login page of the target application. Required for authenticated scans. If provided, `username` and `password` must also be set.
* **username**: Username for authentication. Used with `login_url` and `password`.
* **password**: Password for authentication. Used with `login_url` and `username`.

### Target and Scan Scope

* **target**: The base URL of the application to scan. All scan operations are scoped to this target.

### Performance Parameters

* **scan\_duration\_mins**: Maximum duration (in minutes) for the active scan phase. Controls how long ZAP will attempt to find vulnerabilities using its active scanning engine.
* **spider\_duration\_mins**: Maximum duration (in minutes) for each spider phase. **Important:** This timeout applies separately to both the normal spider and the AJAX spider. For example, if set to 5, each spider will run for up to 5 minutes, potentially doubling the total spidering time.
* **spider\_max\_crawl\_depth**: Maximum depth the spider will crawl from the starting URL. Higher values allow deeper exploration but may increase scan time and resource usage.
* **spider\_max\_children**: Maximum number of child pages the spider will crawl per parent. Controls breadth of exploration and can help limit scan size.

### Internal/Development Parameters

* **api\_key**: API key for ZAP daemon. Used for authentication with the ZAP API.
* **startup\_check\_retries**: Number of times to check if ZAP has started before giving up. Useful for tuning startup reliability in CI/CD environments.
* **startup\_check\_interval**: Seconds to wait between successive ZAP liveness checks during startup.
* **shutdown\_timeout**: Seconds to wait for ZAP to shut down gracefully after scan completion.

## Step-by-Step Workflow

1. **write-metadata**: Writes scan metadata, including the target, for traceability.
2. **run-authenticated-zap-scan**: Launches ZAP, configures authentication (if provided), sets up scan parameters, and orchestrates the scan using both spider and active scan jobs. Handles both normal and AJAX spidering, each with its own timeout (`spider_duration_mins`).
3. **parser**: Parses the SARIF output from ZAP and prepares it for downstream Smithy components.

## Example Usage

You can find a full workflow example in `examples/zap/workflow.yaml`:

## Notes on Spidering

* The **spider\_duration\_mins** parameter is applied to both the normal spider and the AJAX spider. This means that if you set `spider_duration_mins` to 5, the normal spider will run for up to 5 minutes, and then the AJAX spider will also run for up to 5 minutes. This can result in a total spidering time of up to 10 minutes.
* Adjust `spider_max_crawl_depth` and `spider_max_children` to control the depth and breadth of crawling. Higher values may yield more findings but will increase scan time and resource usage.

## Error Handling and Edge Cases

* If any of `login_url`, `username`, or `password` are provided, all three must be set. Otherwise, the scan will fail with a validation error.
* The script will retry ZAP startup according to `startup_check_retries` and `startup_check_interval`.
* If ZAP fails to start or shut down within the specified timeouts, the scan will exit with an error.
* If the target URL is missing or invalid, the scan will not start and an error will be logged.
* If the API key is missing, ZAP will refuse connections and the scan will fail.
* If the spider or active scan durations are set to non-numeric values, defaults will be used and a warning will be logged.
* If authentication fails (e.g., wrong credentials or login page unreachable), the scan will run unauthenticated and log a warning.
* If the output directory or filename is not writable, the scan will fail and log an error.
* If the scan produces no findings, the SARIF report will be empty but still generated.

## Output

* The scan results are written in SARIF format to the file specified by `REPORT_FILENAME` in the directory specified by `REPORT_DIR`. This output is then parsed and made available to downstream Smithy components.
* If the scan fails, partial or error reports may be written for debugging purposes.

## Customization

* You can modify `zap-authenticated-scan.py` to adjust scan logic, authentication methods, or output handling as needed for your environment.

## References

* [ZAP Documentation](https://www.zaproxy.org/docs/)
