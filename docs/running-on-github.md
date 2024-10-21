# Running Smithy using only Github Actions

While the easiest way to run Smithy is on a K8s cluster with a dedicated
enrichment Database using Kustomize to template resources, not everyone has
access to those resources.
A much cheaper (free) way to run smithy is using Github actions directly from
your repository.
This article describes how this works, what is required, considerations/pitfalls
and future plans.

The motivation behind this is to allow open source developers the ability to run
Smithy on their own projects without the need of a cluster.

## Building Blocks

The following are needed in order to run Smithy using Github actions:

* a pipeline setup step
* one or more tools steps and the relevant tool producers
* a step to load the enrichment database
* the enricher and a step to save the enrichment database as an artifact
* one or more consumers

## The setup step

Github actions work very similarly to Tekton(Smithy's runtime engine) so the
setup required is minimal

```yaml
- name: make-dirs
    run: |
    tmp=$(mktemp -d -p $GITHUB_WORKSPACE)
    echo "SMITHY_DIR=$(basename $tmp)" >> $GITHUB_ENV
    echo "GITHUB_WORKSPACE=$GITHUB_WORKSPACE" >> $GITHUB_ENV
    echo "SMITHY_SCAN_ID=$(uuidgen)" >> $GITHUB_ENV
    echo "SMITHY_SCAN_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> $GITHUB_ENV
    mkdir -p $tmp/tool_out $tmp/producer_out $tmp/enricher_out $tmp/enricher_db

```

In this step we make a temporary directory under the current shared Github
Workspace, this directory will hold intermediate output for our steps/tools

Then we save:

* the name of the directory under the `SMITHY_DIR` environment variable
* a unique `SMITHY_SCAN_ID` which the consumers can use to annotate results
* the time the scan started under `SMITHY_SCAN_TIME`
  We also make 3 intermediate directories:
* `tool_out` which contains the output of all our tools. That's where producers
  read from.
* `producer_out` which contains the output of all producers. This is the
  directory the enricher reads from.
* `enricher_out` which contains the enricher's output and is the directory the
  consumers read from.
* `enricher_db` which is used to load and then save the enricher's database
  between runs

## Tooling steps

The following runs a gosec docker image against the current repository and
parses it's output to Smithy's internal format.

```yaml
- name: run_gosec
    run: |
    docker run -v $GITHUB_WORKSPACE:/code  securego/gosec \
               -fmt json \
               -r \
               -no-fail \
               -quiet \
               -out /code/${{ env.SMITHY_DIR }}/tool_out/gosec_out.json \
                /code/...
- name:  parse_gosec
    run: |
    docker run -v $GITHUB_WORKSPACE:/code  \
    thoughtmachine/smithy-producer-gosec \
    -in /code/${{ env.SMITHY_DIR }}/tool_out/gosec_out.json \
    -out /code/${{env.SMITHY_DIR}}/producer_out/gosec-producer_out.pb
```

Gosec:

* `-v $GITHUB_WORKSPACE:/code` mounts our current shared working directory to
  the container's `/code`. The name of the directory in the container is not
  important but it must match the arguments provided to gosec.
* `-fmt json` is important as the gosec parser only understands json
* `-no-fail` instructs gosec to return 0 even if it has findings, this is done
  so that the Github Action continues executing even if Gosec believes there are
  findings.
* `-out /code/${{ env.SMITHY_DIR }}/tool_out/gosec_out.json` instructs the tool
  to write the results to the file `gosec_out.json` located under
  `/code/${{ env.SMITHY_DIR }}/tool_out/`. The variable `${{ env.SMITHY_DIR }}`
  instructs the Github Actions runner to replace it with the value of the
  environment variable `SMITHY_DIR`

The producer:

* Mounts the same workspace under `/code`
* Uses the argument `-in` (common in all producers) to read the tool's output
  from the file `gosec_out.json` located in the path
  `/code/${{ env.SMITHY_DIR }}/tool_out/`
* Uses the argument `-out` (common in all producers) to write the producer's
  output to the protobuff file
  `/code/${{env.SMITHY_DIR}}/producer_out/gosec-producer_out.pb`

## Enrichment

Due to Github's lack of a persistent database this step is the most complicated:

```yaml
- name: fetch_db
    uses: northdpole/smithy-load-latest-database-action@v0
    with: 
    OUTPUT_DIR: ${{github.workspace}}/${{ env.SMITHY_DIR}}/enricher_db/
- name: run_enricher
    run: |
    sudo apt update && sudo apt install -y postgresql-client

    docker run -d -e POSTGRES_HOST_AUTH_METHOD=trust \
               --rm -p 5432:5432 postgres:13.6
    sleep 5 # give postgress time to start
    docker ps

    if [ -f $GITHUB_WORKSPACE/${{ env.SMITHY_DIR}}/enricher_db/db.dump ]; then
        psql -e -h 127.0.0.1 -p 5432 -U postgres \
             -f $GITHUB_WORKSPACE/${{ env.SMITHY_DIR}}/enricher_db/db.dump
        rm -f $GITHUB_WORKSPACE/${{ env.SMITHY_DIR}}/enricher_db/db.dump
    fi

    export ENRICHER_READ_PATH=/code/${{ env.SMITHY_DIR }}/producer_out/
    export ENRICHER_WRITE_PATH=/code/${{ env.SMITHY_DIR }}/enricher_out/
    export ENRICHER_DB_CONNECTION='host=127.0.0.1 port=5432 user=postgres\
     sslmode=disable' 

    docker run --network host -v $GITHUB_WORKSPACE:/code -e ENRICHER_READ_PATH \
               -e ENRICHER_WRITE_PATH \
               -e ENRICHER_DB_CONNECTION thoughtmachine/smithy-enricher:latest

    pg_dump -h 127.0.0.1 -p 5432 -d postgres -U postgres -w -Fp --clean \
            --no-owner --no-privileges --no-acl --if-exists --inserts \
            --no-comments >\
             $GITHUB_WORKSPACE/${{ env.SMITHY_DIR }}/enricher_db/db.dump
    
- uses: actions/upload-artifact@v2
    with:
    name: smithy_enrichment_db
    path: ${{ env.GITHUB_WORKSPACE }}/${{ env.SMITHY_DIR }}/enricher_db/db.dump
    if-no-files-found: error
    retention-days: 90 # 3 months of backups should be enough

```

The step `fetch_db` uses a script located
[here](https://github.com/northdpole/smithy-load-latest-database-action/blob/main/get_latest_artifact.py)
to find the latest artifact named `smithy_enrichment_db` by creation date and
attempts to download and extract it in the path denoted by `OUTPUT_DIR`.

The step `run_enricher` starts by installing psql and pg\_dump in order to be
able to load and save the database and running a temporary postgres container
so that the enricher has a database to connect to.
The following attempts to load the database if the step `fetch_db` managed to
find one in the artifacts:

```bash
    if [ -f $GITHUB_WORKSPACE/${{ env.SMITHY_DIR}}/enricher_db/db.dump ]; then
        psql -e -h 127.0.0.1 -p 5432 -U postgres \
             -f $GITHUB_WORKSPACE/${{ env.SMITHY_DIR}}/enricher_db/db.dump
        rm -f $GITHUB_WORKSPACE/${{ env.SMITHY_DIR}}/enricher_db/db.dump
    fi
```

Then the enricher variables are setup and the enricher runs with.

```bash
export ENRICHER_READ_PATH=/code/${{ env.SMITHY_DIR }}/producer_out/
export ENRICHER_WRITE_PATH=/code/${{ env.SMITHY_DIR }}/enricher_out/
export ENRICHER_DB_CONNECTION='host=127.0.0.1 port=5432 user=postgres\
 sslmode=disable' 

docker run --network host -v $GITHUB_WORKSPACE:/code -e ENRICHER_READ_PATH \
            -e ENRICHER_WRITE_PATH \
            -e ENRICHER_DB_CONNECTION thoughtmachine/smithy-enricher
```

Please note that the enricher will run migrations therefore creating the
necessary database structure if the necessary database tables do not exist.

Finally, we save the database by dumping the running db and using the
`upload-artifact` action to save it as a github artifact for 90 days
(configurable)

```bash

    pg_dump -h 127.0.0.1 -p 5432 -d postgres -U postgres -w -Fp --clean \
            --no-owner --no-privileges --no-acl --if-exists --inserts \
            --no-comments > $GITHUB_WORKSPACE/${{ env.SMITHY_DIR }}/enricher_db/db.dump
```

```yaml
- uses: actions/upload-artifact@v2
    with:
    name: smithy_enrichment_db
    path: ${{ env.GITHUB_WORKSPACE }}/${{ env.SMITHY_DIR }}/enricher_db/db.dump
    if-no-files-found: error
    retention-days: 90 # 3 months of backups should be enough
```

## Consumers

In this example we used the simplest consumer, `stdout-json` which just prints
the results. You can use any of the supported consumers or write your own if
required.

```yaml
- name: run_stdout_consumer
    run: |
    docker run -e SMITHY_SCAN_ID -e SMITHY_SCAN_TIME \
               -v $GITHUB_WORKSPACE:/code \
                thoughtmachine/smithy-consumer-stdout-json:v0.16.0 \
                -in /code/${{ env.SMITHY_DIR}}/enricher_out/
```

The consumer is supplied with

* One volume mount `-v $GITHUB_WORKSPACE:/code thoughtmachine/`
* The environment variables we setup at the beginning: `SMITHY_SCAN_ID`
  and `SMITHY_SCAN_TIME`
* One argument, common to all consumers `-in` which points to the path where the
  enricher wrote it's results,  `${{ env.SMITHY_DIR}}/enricher_out/`

More complicated consumers such as slack or jira would also require extra
variables (a webhook url for slack, jira credentials for jira) and in case of
the Jira consumer, a configuration file as described in it's documentation page

## Considerations

The following are considerations/pitfalls you should be aware off when runnign
smithy as a github action:

* The variable `SMITHY_SCAN_ID` needs to be a uuid4
* The variable `SMITHY_SCAN_TIME` needs to be an RFC3339 type timestamp, the
  `date` utility does not support timezones when it is run with
  `date --rfc-3339=seconds` and, to our knowledge, there is no way to make it
  output a timestamp in the correct format.
