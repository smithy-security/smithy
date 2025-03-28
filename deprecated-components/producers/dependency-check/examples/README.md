# Examples

## requirements.txt

```bash
# Install dependency-check, e.g. using brew:
brew update && brew install dependency-check

# The python analyser is "experimental", so need to enable it explicitly
dependency-check --out . --scan requirements.txt -f JSON --enableExperimental

go run ../main.go -in ./dependency-check-report.json -out ./dependency-check.pb
```
