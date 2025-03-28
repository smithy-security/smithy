# Examples

## go.mod

```bash
go list -m all | nancy sleuth -o json > result.json

# Must be run from one folder up, otherwise go gets
# confused about dependencies
cd ../
go run main.go -in ./examples/result.json -out ./examples/result.pb
```
