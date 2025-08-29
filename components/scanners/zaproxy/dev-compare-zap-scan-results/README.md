# Dev Compare ZAP Scan Results\\

This utility is meant to be used by developers to compare ZAP reports when running the tool via its UI vs when running with the automation framework

## How to use

* Install ZAP from its website or based on your package manager.
* Launch ZAP via its UI
* Run a quick-scan towards the website you want to test, e.g. https://smithy.security
* Click 'Report' in the menu and generate a Sarif report
* Save teh SARIF report somewhere accessible by your terminal
* In your terminal:
* `cd` in  the 'zap-authenticated-scan' directory
* Build the image with `docker build . -t zap-test`
* Run the image as such:

```bash
docker run \
  -v "$(pwd)":/code \
  -e API_KEY="foobar" \
  -e TARGET="https://smithy.security" \
  -e REPORT_DIR="/code" \
  -e SPIDER_DURATION_MINS=5 \
  -e SCAN_DURATION_MINS=15 \
  -ti zap-test | tee /tmp/zap.txt > /dev/null
```

* This will create a `.json` sarif file in the current dir.
* `cd` in this directory and run the utility to compare results with:

```bash
go run main.go --sarif1 <the automation script report> --sarif2 <the zap gui report>
```
