If you want to run a workflow with a component by the Python SDK, there are some additional steps you need to do first.

Firstly, you have to make sure that the component is living in the smithy repo in the correct place 
- likely `smithy/components/enrichers/{component_folder}`


Then, in `saas` you need to update the `findings-service`'s ports to `5001:5001`.

Modify `saas/cmd/findings-service/docker-compose.yaml` and add the lines 

```
ports:
  - "50051:50051"
```

The file should look something like 

```
services:
  findings-service:
    build:
      context: ../..
      dockerfile: containers/findings-service.Dockerfile
    platform: linux/amd64
    env_file:
      - ./.env
    depends_on:
      findings-db:
        condition: service_healthy
    ports:
      - "50051:50051"
  findings-db:
    image: postgres:15
    container_name: findings-db
  ...rest of the file
```

You also need to create a .env file in the same directory.

In this file put

```
DB_DSN=postgresql://smithy:smithy1234@findings-db:5432/findings-db?sslmode=disable&connect_timeout=10
IS_LOCAL=true
FINDINGS_SERVER_ADDR=0.0.0.0:50051
```

Then, in a terminal navigate to `saas/cmd/findings-service/` and run `docker compose up`.
This should launch successfully, but will show this error.

```
findings-service-1  | {"time":"2025-08-14T11:53:57.853165621Z","level":"DEBUG","msg":"Server listening...","address":"[::]:50051"}
findings-db         | 2025-08-14 11:54:02.318 UTC [83] FATAL:  role "postgres" does not exist
findings-db         | 2025-08-14 11:54:07.383 UTC [91] FATAL:  role "postgres" does not exist
findings-db         | 2025-08-14 11:54:12.443 UTC [99] FATAL:  role "postgres" does not exist
```

This is fine and can be ignored.


Like a normal running workflow, you will need a `workflow.yaml` file and a `overrides.yaml` file.

Here are two example ones you can make

overrides.yaml
```
git-clone:
- name: "repo_url"
  type: "string"
  value: "https://github.com/saibamo/TestRepo.git"
- name: "reference"
  type: "string"
  value: "changed-main"
- name: "base_reference"
  type: "string"
  value: "main"
auto-remediation:
- name: anthropic_token
  type: string
  value: "no_token"
- name: google_token
  type: string
  value: "no-token"
```

workflow.yaml
```
description: Workflow to test the Auto Remediation Enricher
name: auto_rem
components:
- component: file://components/targets/git-clone/component.yaml
- component: file://components/scanners/bandit/component.yaml
- component: file://components/enrichers/auto-remediation/component.yaml
- component: file://components/reporters/json-logger/component.yaml
```

For each component in the workflow you are running, you need to update the `env_vars` in the `components.yaml` with the following lines

```
SMITHY_STORE_TYPE: "findings-client"
SMITHY_REMOTE_STORE_FINDINGS_SERVICE_ADDR: "172.17.0.1:50051"
```

E.g. for the `git-clone` component the file will look something like

```
name: git-clone
description: "Clones a repository"
type: target
parameters:
  - name: repo_url
    type: string
    value: https://github.com/sqreen/go-dvwa.git
  - name: reference
    type: string
    value: master
  - name: username
    type: string
    value: ""
  - name: token
    type: string
    value: ""
  - name: base_reference
    type: string
    value: ""
steps:
  - name: clone-repo
    env_vars:
      GIT_CLONE_REPO_URL: "{{ .parameters.repo_url }}"
      GIT_CLONE_ACCESS_USERNAME: "{{ .parameters.username }}"
      GIT_CLONE_ACCESS_TOKEN: "{{ .parameters.token }}"
      GIT_CLONE_REFERENCE: "{{ .parameters.reference }}"
      GIT_CLONE_BASE_REFERENCE: "{{ .parameters.base_reference }}"
      GIT_CLONE_PATH: "{{ sourceCodeWorkspace }}"
      GIT_CLONE_TARGET_METADATA_PATH: "{{ targetMetadataWorkspace }}"
      GIT_RAW_DIFF_PATH: "{{ targetMetadataWorkspace }}"
      SMITHY_STORE_TYPE: "findings-client"
      SMITHY_REMOTE_STORE_FINDINGS_SERVICE_ADDR: "172.17.0.1:50051"
    image: components/targets/git-clone
    executable: /bin/target
```

Finally, you can run this example workflow with the command 

```
smithyctl workflow run --overrides=examples/auto_rem/overrides.yaml --build-component-images=true examples/auto_rem/workflow.yaml > test.log
```

This will run the workflow, and output the logs to `test.log`



