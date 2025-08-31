# MobSF Orchestrator

A testable Go program that orchestrates MobSF (Mobile Security Framework).

## Configuration

The orchestrator is configured via environment variables:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `MOBSF_DIR` | Directory containing MobSF installation | `/home/mobsf/Mobile-Security-Framework-MobSF` | Yes |
| `MOBSF_API_KEY` | API key for MobSF authentication | Auto-generated UUID | Yes |
| `MOBSF_HOST` | Host address for MobSF | `127.0.0.1` | No |
| `MOBSF_PORT` | Port for MobSF | `8000` | No |
| `MOBSF_CLIENT_REQUEST_TIMEOUT` | General timeout for operations | `30s` | No |
| `MOBSF_CLIENT_MAX_RETRIES` | Maximum retry attempts | `3` | No |
| `MOBSF_CLIENT_RETRY_DELAY` | Delay between retries | `5s` | No |
| `MOBSF_STARTUP_TIMEOUT` | Maximum time to wait for startup | `2m` | No |
| `MOBSF_SCANNED_FILE_PATH` | Path to the file to be scanned | - | Yes |
| `MOBSF_REPORT_OUTPUT_PATH` | Path where the report will be saved | - | Yes |
| `MOBSF_SCAN_COMPLETION_BACKOFF` | Initial backoff duration for scan completion retries | `1s` | No |
| `MOBSF_SCAN_COMPLETION_MAX_BACKOFF` | Maximum backoff duration for scan completion retries | `300s` | No |
| `MOBSF_ORCHESTRATOR_LOG_LEVEL` | Logging level (debug, info, warn, error) | `info` | No |

## Usage

### Basic Usage

```bash
# Set required environment variables
export MOBSF_DIR="/path/to/mobsf"
export MOBSF_API_KEY="your-api-key"
export MOBSF_SCANNED_FILE_PATH="/path/to/file.apk"
export MOBSF_REPORT_OUTPUT_PATH="/path/to/report.json"

# Run the orchestrator
go run cmd/main.go
```

### With Custom Configuration

```bash
export MOBSF_DIR="/opt/mobsf"
export MOBSF_API_KEY="your-secure-api-key"
export MOBSF_HOST="0.0.0.0"
export MOBSF_PORT="9000"
export MOBSF_CLIENT_REQUEST_TIMEOUT="60s"
export MOBSF_CLIENT_MAX_RETRIES="5"
export MOBSF_SCAN_COMPLETION_BACKOFF="2s"
export MOBSF_SCAN_COMPLETION_MAX_BACKOFF="60s"
export MOBSF_ORCHESTRATOR_LOG_LEVEL="debug"
export MOBSF_SCANNED_FILE_PATH="/path/to/file.apk"
export MOBSF_REPORT_OUTPUT_PATH="/path/to/report.json"

go run cmd/main.go
```

## Testing

```bash
# Run all tests
go test -v

# Run specific test
go test -v -run TestLoadConfig

# Run tests with coverage
go test -v -cover
```

## Building

```bash
# Build the binary
go build -o mobsf-orchestrator cmd/main.go

# Build with version information
go build -ldflags "-X main.Version=v1.0.0 -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.GitCommit=$(git rev-parse --short HEAD)" -o mobsf-orchestrator cmd/main.go
```
