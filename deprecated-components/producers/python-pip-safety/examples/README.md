# Examples

## requirements.txt

```bash
pip install safety

safety --version
# safety, version 3.2.3

safety check -r requirements.txt --save-json ./result.json

go run ../main.go -in ./result.json -out ./result_safety.pb
```
