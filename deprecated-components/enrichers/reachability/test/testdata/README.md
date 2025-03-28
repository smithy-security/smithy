# Testdata

## How to generate tagged files

Find a python repository with vulnerabilities,
for example [fportantier/vulpy](https://github.com/fportantier/vulpy).

### bandit.tagged.pb

1. Checkout [bandit](https://github.com/PyCQA/bandit).
2. Get a bandit report in json format:
   `bandit -r $directory --format json --output out.json`.
   `$directory` is where you cloned the repository with vulnerabilities.
3. Get `/producer/python-bandit` to read in input `out.json`
   and in output `out.tagged.pb`.

### pip-safety.tagged.pb

1. Checkout [safety](https://pypi.org/project/safety/)
2. Get a safety report in json format:
   `safety check -r requirements.txt --save-json out.json`
3. Get `producer/python-pip-safety` to read in input `out.json`
   and in output `pip-safety.tagged.pb`

### reachables.json

1. Checkout [atom](https://github.com/AppThreat/atom)
2. Run `cdxgen -t $lang --deep -o bom.json .`
3. Run `atom reachables -o app.atom -s reachables.json -l $lang .`
