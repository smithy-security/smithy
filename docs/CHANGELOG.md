## 

**v0.57.0**
2024-10-22T12:20:21+01:00: add changelog binary that allows to generate a changelog consisting of commit messages between defined tag and HEAD
2024-10-22T12:18:06+01:00: add changelog target to the makefile
2024-10-16T11:33:41+01:00: remove results output from git-clone component
**v0.56.5**
2024-10-23T21:56:39+01:00: fix bug #445, make the jira issue type configurable
2024-10-31T11:02:12Z: workaround defectdojo expecting a non-empty scanstarttime for their engagments
**v0.56.4**
2024-10-30T14:57:59Z: fix #453 by providing an optional nvdApiKey to dependency-check
**v0.56.3**
2024-10-30T17:37:44Z: Updating component runners to leverage WorkflowID.
2024-10-30T17:37:22Z: Refreshing examples to take WorkflowID in account.
2024-10-30T17:36:54Z: Leverage Workflow ID for the runner.
2024-10-30T11:55:35Z: Implementing base for SQLite local storage.
2024-10-30T17:35:41Z: Passing WorkflowID to storage methods and regenerating mocks
2024-10-30T17:34:13Z: Adding reusable uuid package.
2024-10-30T11:54:58Z: Adding SQLite dependencies and vendors.
2024-10-29T10:45:30Z: Adding docs and examples.
**v0.56.2**
2024-10-29T10:45:13Z: Implementing components on top of the runner.
2024-10-29T10:43:19Z: Implementing shared runner and basic storer
2024-10-29T10:42:58Z: Adding utilities for runner and components.
2024-10-29T10:40:37Z: Updating component interfaces and regenerating mocks.
2024-10-29T10:39:58Z: Adding dependencies for runner; adding means to generate mocks; adding basic version.
2024-10-25T11:30:48+01:00: example workflow for scorecard
**v0.56.1**
2024-10-25T11:50:07+01:00: nit: set the default annotation of the custom annotation enricher to the empty map so that it doesn't crash if its run as a noop
2024-10-25T11:49:24+01:00: bugfix #448, make scorecard binary work
2024-09-02T20:27:56+01:00: dependencies, update playwright-go
**v0.56.0**
2024-10-24T16:22:16+01:00: add example testdata for easier unittests
2024-10-24T16:21:56+01:00: add a pluggable aws-s3 wrapper
2024-10-24T16:21:30+01:00: support the pdf consumer with a pluggable playwright wrapper
2024-10-24T16:20:57+01:00: address #332, make the pdf consumer play well with the rest of the build system
2024-10-24T13:42:20+01:00: feature/update-the-logos-for-readme (#442)2024-10-21T12:47:25+01:00: Formatting docs.
2024-10-21T12:47:15+01:00: Updating getting started docs to fix a malformed pipelines deploy command.
2024-10-21T12:04:47+01:00: Update reviewdog references to smithy.
**v0.55.4**
2024-10-21T12:04:31+01:00: Updating .gitignore to ignore smithy files previously ignored by ocurity.
2024-10-21T12:04:07+01:00: Updating actions to leverage smithy references.
2024-10-21T12:03:25+01:00: Updating tests to leverage smithy.
2024-10-21T12:03:12+01:00: Updating lock.
2024-10-21T12:02:54+01:00: Update README to replace ocurity with smithy.
2024-10-21T12:02:21+01:00: Updating protobuf contracts to use smithy as reference.
2024-10-21T12:02:01+01:00: Updating docs to use smithy references.
2024-10-21T12:01:39+01:00: Updating examples to leverage smithy.
2024-10-21T12:01:20+01:00: Renaming utilities and deployment references from ocurity/dracon to smithy-security/smithy
2024-10-21T12:00:30+01:00: Renaming go references from ocurity/dracon to smithy-security/smithy
2024-10-18T11:12:42+01:00: nit: improve logging for the custom annotation enricher and adjust the name of its parameter in the example
2024-10-08T13:01:28+01:00: github security example workflow
2024-10-07T18:54:52+01:00: upgrade the github library to v65
2024-10-07T18:54:27+01:00: add a github wrapper package
2024-10-07T18:53:08+01:00: feature/402 dependabot producer2024-10-07T18:52:14+01:00: feature/401-github-codeql producer2024-10-18T09:39:01+01:00: Defining component SDK interfaces.
2024-10-18T09:38:41+01:00: Moving OCSF generated code to the SDK for better reuse.
2024-10-15T10:17:35+01:00: fix #422, allow consumer templating to also carry information about which annotation contains the code fix
**v0.55.3**
2024-10-16T14:04:48+01:00: Reverting changes to see if we could not expand vendors in PR review diffs as it doesn't work.
**v0.55.2**
2024-10-16T13:43:01+01:00: Attempting to not expand vendors in PR Diffs.
2024-10-16T12:52:28+01:00: Do not expand vendor/ changes on PR Diffs.
2024-10-15T17:34:50+01:00: Generating OCSF Go types from Proto Schema.
2024-10-11T19:59:16+01:00: fix bug 418 typo while checking jira issue count
**v0.55.1**
2024-10-11T15:59:16+01:00: Removing unused imports.
2024-10-11T15:12:10+01:00: fix bug #414 where the jira consumer would not create issues with zero scanstart time
2024-10-14T11:39:15+01:00: Adding utilities to run buf in Docker.
2024-10-12T19:23:14+01:00: Bumping buf to v2 to build correctly and removing out of date or unused configuration. Bumping proto plugins to latest.
2024-10-11T18:32:36+01:00: temporarily remove scan start time from jira consumer
**v0.55.0**
2024-10-11T17:34:09+01:00: Adding script to cleanup sample output from json consumer
2024-10-11T00:10:52+01:00: nit, slightly change the error of the custom annotation enricher to show what was the object that could not be unmarshalled
**v0.54.0**
2024-10-10T23:48:04+01:00: close #409, refactor Jira consumer, remove addToDescription, instead offer a default template
2024-10-10T22:49:20+01:00: close feature #407 create a snyk node producer
2024-10-11T09:48:41+01:00: fix issue happening mostly with semgrep where issues would not be enriched due to the type being more than 128 characters
2024-10-03T17:22:14+01:00: nit:change the golang example to use a dedicated go vulnerable web app
**v0.53.0**
2024-10-03T17:01:41+01:00: implement #394 - add a custom key-value pair enricher
2024-10-03T16:57:51+01:00: fix issue #393 by adjusting the default workspace for the source-code
2024-10-03T15:25:30+01:00: #391: add tagging utilities
**v0.52.1**
2024-10-03T15:20:50+01:00: #389: fix ts eslint wrapper image reference
2024-10-02T12:21:04+01:00: relax elasticsearch consumer's definition of an error, make it accept all 200s as a valid response from the server
**v0.52.0**
2024-10-01T23:04:39+01:00: fix the reachability enrichers atom run command by removing backslashes
**v0.51.1**
**v0.51.0**
2024-09-26T12:19:26+01:00: fix #379, add significantly more error logging to the elasticsearch consumer
**v0.50.1**
2024-09-27T19:33:42+01:00: add snyk-python to the test workflow
2024-09-27T19:31:56+01:00: implement #381 snyk for python
2024-09-27T19:31:25+01:00: fix #382 by rewriting the snyk orchestration script
2024-09-24T12:19:14+01:00: temporarily remove cyclonedx parsing from the checkov producer to comply with the convention that each producer has 1 single producer-issues step
**v0.50.0**
2024-09-24T09:17:46+01:00: downgrade buf to 1.28.1 to prevent proto formatting false positives
**v0.49.0**
2024-09-24T09:11:13+01:00: fix deprecated reviewdog flag in lint make target
2024-09-20T09:48:26+01:00: bugfix/367 fix cyclonedx parser crash if the package does not have purl in metadata
2024-09-19T19:09:03+01:00: example checkov workflow
2024-09-19T19:08:13+01:00: implement feature 356, minimal checkov producer
2024-09-17T11:31:25+01:00: brakeman rails project test workflow
2024-09-16T17:25:02+01:00: feature/358 introduce brakeman producer
2024-09-23T15:47:10+01:00: set all parameters in es consumer to the default empty string
2024-09-22T09:09:34+01:00: update publish checkout action to v4
2024-09-19T15:16:31+01:00: Updating example Kustomization to rely on correct local components paths.
**v0.48.0**
2024-09-19T15:15:58+01:00: Moved from original getting-started.md document so they can be checked out separately.
2024-09-19T15:14:58+01:00: Refreshing Getting Started document to be more user friendly and to the point.
2024-09-19T15:14:11+01:00: Linking Discord server.
2024-09-18T21:47:34+01:00: bugfix:364 fix sarif parser bug where if no endline was provided the output would end in '-'
2024-09-18T21:40:29+01:00: nit: add an info log for where a producer wrote its output
2024-09-18T21:34:59+01:00: example snyk workflow
**v0.47.0**
2024-09-18T21:33:21+01:00: issue 362 a base snyk producer that supports snyk docker
2024-09-19T11:51:27+01:00: Simplifying purl parsing and reachability flow for atom reachability enricher.
**v0.46.0**
2024-09-17T16:19:16+01:00: Adding example pipeline for atom reachability enricher.
**v0.42.0**
2024-09-17T16:18:52+01:00: Adding task for atom reachability enricher.
2024-09-17T16:18:31+01:00: Adding business logic and tests for atom reachability enricher.
2024-09-16T10:18:02+01:00: Adding base Golang code styling documentation location with sample rules; Moving enumeration generation document to the go styling folder.
2024-09-22T00:24:17+01:00: fix draconctl path in publish job
2024-09-11T15:21:10+01:00: Extending docs with sections about custom container platform and OS/ARCH for building binaries. Bumping remark-cli to suppress errors and warnings on linting markdown files.
2024-09-11T15:19:56+01:00: Formatting pdf Dockerfile.
2024-09-11T15:17:06+01:00: introduce multi-platform builds #3342024-09-13T21:30:36+01:00: fix 349 by adding api keys to the elasticsearch consumer so that it can work with elasticsearch saas
**v0.41.0**
2024-09-13T14:38:57+01:00: simplify producer aggregator build
2024-09-13T14:38:19+01:00: remove github-code-scanning makefile and dockerfile
2024-09-12T20:26:52+01:00: make producer aggregator work with new base image
2024-09-12T20:22:34+01:00: remove scratch as the explicit BASE_IMAGE in the makefile
2024-09-12T20:26:14+01:00: change all docker and makefiles from components that needed certificates since now the base image has certs
2024-09-12T20:24:00+01:00: make build component containers script build using a base dockerfile that has certificates
2024-09-12T17:59:26+01:00: fixup! fix CONTAINER_REPO for dev-* targets and Makefile formatting
2024-09-12T17:33:06+01:00: fix CONTAINER_REPO for dev-* targets and Makefile formatting
2024-09-12T17:30:50+01:00: fix nit to prevent warnings from docker build daemon
2024-09-10T11:30:17+01:00: fix-bug-341-postgreql-does-not-have-credentials
**v0.40.0**
2024-08-31T13:25:26+01:00: fix #330 by making the dependency track consumer debug flag into a string instead of a boolean switch
**v0.38.0**
2024-09-05T11:53:41+01:00: Revert and then improve footnotes on deploying custom Dracon components.
2024-09-05T10:53:03+01:00: Removing ThoughtMachine mentions from README.
2024-09-04T18:03:20+01:00: Fixing markdown formatting warns and errors.
2024-09-04T16:26:51+01:00: Ignore .idea/ generated by IntelliJ IDEs to prevent maintainers from accidentally pushing changes to it.
2024-09-04T16:25:25+01:00: 🐛 Fix undefined key error highlighted by Helm as the required database key was missing.
2024-09-04T16:24:08+01:00: 🐛 Fix getting started formatting and content.
2024-09-04T16:23:40+01:00: 🐛 Fix README formatting, content and links.
2024-08-30T22:04:28+01:00: fix #328 by changing the BOM upload method from UploadBom to PostBOm, as PostBom does not have a size limitation
2024-08-30T22:02:44+01:00: fix #329 by removing log.Fatal outside main method and adding structured logging and error returning to the Dependencty Track Consumer
2024-08-30T22:00:35+01:00: fix #327 by renaming the dependency track consumer debug flag
2024-08-30T16:03:22+01:00: fix reference to image.repository in deduplication migrations reference to not include deduplication_db_migrations dictionary
**v0.37.0**
2024-08-30T12:07:15+01:00: remove -quiet from gosec for visibility
**v0.36.0**
2024-08-27T18:12:50+01:00: add dockerfile with certs
2024-08-25T22:31:31+01:00: add parameter checking and debugging to dt consumer
2024-08-25T22:29:18+01:00: upgrade the dt library version
2024-08-25T22:26:34+01:00: upgrade cdxgen to the latest version
2024-08-14T12:22:53+01:00: make the migrations role optional
2024-08-14T12:22:36+01:00: allow overriding image names
2024-08-22T15:42:14+01:00: fix ossf scorecard custom docker building and publishing
**v0.35.0**
2024-08-22T15:20:14+01:00: add dependency check to the sca kustomization
2024-08-22T15:10:36+01:00: fix zaproxy image
2024-08-22T14:37:59+01:00: make cyclonedx report how many components it imported
2024-08-21T21:47:00+01:00: make source-code the default subdir
2024-08-20T14:18:54+01:00: 💬 Add descriptions for all components
2024-08-19T21:34:37+01:00: iclose #307 by making addanchors and add env vars idempotent
2024-08-19T20:16:07+01:00: close #309, add certificates to jira consumer
**v0.32.0**
2024-08-12T09:58:05+01:00: nit: rename old enrichment db migrations pod to deduplication db migrations
2024-08-08T17:03:51+01:00: Revert "👷 Add E2E integration test to CI"2024-08-09T10:08:18+01:00: add label to draconctl container
2024-08-08T16:50:51+01:00: make migrations tests ignore structured logging
**v0.31.0**
2024-08-08T16:38:23+01:00: remove positional migrations path from job in favour of the env var
2024-08-08T15:46:51+01:00: ensure that the migrations dir exists
2024-08-08T15:46:15+01:00: add info log to draconctl migrations for which dir it picks up migrations from
2024-08-07T17:55:20+01:00: 👷 Add E2E integration test to CI
2024-08-08T15:04:10+01:00: fix quoting of deduplication enricher environment variables (closes #163)
**v0.28.0**
2024-08-08T14:05:55+01:00: add resources and pull policy to the migrations job
2024-08-08T14:13:13+01:00: fix deduplication enricher environment variables (closes #294)
2024-08-07T17:44:52+01:00: 🐛 Fix bug in `make install` target
2024-08-07T16:40:03+01:00: 🐛 Fix incorrect `ocurity/dracon` prefix for local components
2024-08-07T09:08:43+01:00: make deduplication db component have expected db connection string values
2024-08-07T09:19:59+01:00: remove helm image registry from global values
2024-08-07T09:18:48+01:00: introduce install and dev-deploy makefile targets2024-08-06T16:40:27+01:00: replace container_registry with image.registry Helm parameter and re-use dev Dracon Helm values (closes #289)
**v0.27.0**
2024-08-06T16:22:42+01:00: remove image pinning logic from Helm package creation command
2024-08-06T15:40:10+01:00: cleanup leftover chart dependencies
2024-08-06T15:39:46+01:00: fix path in .gitignore
2024-08-03T19:19:32+01:00: fix example producer image URL (part of #287)
2024-08-03T19:18:54+01:00: fix dependency track image URL (part of #287)
2024-08-03T19:18:35+01:00: use Helm Chart app version as a tag for component images (part of #287)
2024-08-03T19:13:28+01:00: parallelize docker builds in github publish action
2024-08-05T15:54:16+01:00: 🔧 Add support for overriding `enrichers/deduplication` connection string2024-07-12T13:20:48+01:00: make draconctl able to log JSON
2024-08-01T13:34:01+03:00: 🔊 Change log level to `debug` for missing scan tags
2024-08-01T13:33:27+03:00: 🗃️ Add SCA example pipeline
2024-08-01T13:21:53+03:00: 🔧 Add sensible default to trivy producer
2024-08-01T12:04:24+03:00: ⬆️ Upgrade trivy `0.37.1->-0.54.1`
2024-08-01T12:03:50+03:00: 🔊 Make trivy logging more verbose
2024-08-01T11:48:41+03:00: 🐛 Fix incorrect reference to binary
2024-08-02T13:31:23+01:00: remove namespace reference from enricher deduplication database URI
**v0.26.0**
2024-07-30T13:56:43+03:00: ⬆️ Bump `actions/setup-go@v4` to `v5`
**v0.25.0**
2024-07-30T13:50:02+03:00: 👷 Add test summary for Go tests
2024-07-30T13:43:24+03:00: 👷 Replace `go test` with `gotestsum`
2024-07-30T17:09:13+03:00: 💬 Add parameter descriptions to `consumers/slack`
2024-07-30T15:58:35+03:00: 🧱 Add custom `Dockerfile` for `consumers/slack`2024-07-30T18:59:43+03:00: ⬆️ Run `go mod vendor`
2024-07-30T18:59:31+03:00: ➕ Add `go-github` as a dependency
2024-07-29T16:19:32+03:00: 🗃️ Add GHAS example pipeline
2024-07-29T15:09:15+03:00: 🗃️ Add example data for `producer/github-code-scanning`
2024-07-29T13:42:55+03:00: ✨ Add new `producer/github-code-scanning` component
2024-06-06T08:57:07+01:00: 🐛 Fix Semgrep and Bandit producers not recording CWE
2024-07-24T14:19:01+03:00: 🐛 Fix enrichers not handling multiple tools
2024-07-24T14:14:19+03:00: 🔧 Change example python pipeline
2024-07-24T14:13:59+03:00: 🔧 Change example golang pipeline
2024-07-24T12:44:36+03:00: ♻️  Refactor image pinning test
2024-07-24T12:39:59+03:00: 🐛 Fix typescript example workflow
2024-07-23T12:54:50+03:00: 🔨 Add utility script to bump local components
2024-07-23T18:05:05+03:00: 🐛 Fix `producer/semgrep` fails to run2024-07-23T17:30:12+03:00: 🐛 Fix `producer/eslint` component not starting
2024-07-23T16:36:06+03:00: 🐛 Fix erroneous image reference in `eslint` producer
2024-07-18T17:20:15+02:00: 🐛 Fix `producer/yarn-audit` not handling empty lines2024-07-18T17:30:31+02:00: 🐛 Fix incorrect parameter name in TS example pipeline
2024-07-18T17:01:28+02:00: 🔧 Replace `enricher-deduplication` with `enricher-codeowners` in examples
2024-07-18T17:00:31+02:00: 🔧 Change default ES and MongoDB URLs
2024-07-11T14:18:47+01:00: ♻️  Refactor all enrichers to always produce results
2024-07-11T14:18:28+01:00: ✅ Introduce `enrichers/test_utils.go`
2024-07-11T12:47:58+01:00: ♻️  Extract `enricher/depsdev` types into own file
2024-07-29T20:49:41+01:00: fix broken zaproxy task by removing typo
2024-07-29T20:49:23+01:00: fix unrunable task by adding a command for testssl.sh
2024-07-12T16:37:41+01:00: ♻️  Switch `producers/typescript-eslint` to produce file targets2024-07-12T16:01:01+01:00: ♻️  Switch `producers/semgrep` to produce file targets2024-07-12T08:41:59+01:00: ♻️  Switch `producers/golang-gosec` to produce file targets2024-07-12T08:39:51+01:00: ✨ Add `ExtractCode` for fileURI targets2024-07-11T15:58:33+01:00: ✨ Add `GetFileTarget` and `EnsureValidFileTarget` to base producer
2024-07-24T18:26:26+01:00: 🔥 Remove dead code in enricher-aggregator2024-07-17T19:50:52+01:00: deduplication migrations: fix migrations path and hook delete policy (Fixes OCU-150, OCU-151)
**v0.23.0**
2024-07-15T11:48:02+01:00: ♻️  Refactor `producer.ReadInFile` to use `os.ReadFile`
2024-07-09T12:22:30+01:00: 🔥 Remove `producers/typescript-npm-audit`
2024-07-08T17:07:31+01:00: 🧐 Add example data for `producers/npm-audit`
2024-07-08T17:07:15+01:00: ✨ Switch npm audit producer to record pURL targets
2024-07-08T16:37:56+01:00: 🔥 Remove deprecated `producers.ReadLines`
2024-07-08T16:37:32+01:00: 🐛 Fix broken yarn audit producer
2024-07-08T16:31:13+01:00: 🧐 Add example data for `producers/typescript-yarn-audit`
2024-07-08T14:57:07+01:00: ✨ Expand `producer/golang-nancy` to record CWE and pURL target
2024-07-08T14:55:52+01:00: 🧐 Add example data for `producers/golang-nancy`
2024-07-17T19:50:52+01:00: remove hooks from deduplication job and simplify parameters
2024-07-17T16:08:14+01:00: fix deduplication migrations Helm package name in publish action
**v0.22.0**
2024-07-17T15:47:17+01:00: fix for GH publish action
**v0.21.0**
2024-07-16T16:54:19+01:00: fix #255 by making the enricher aggregator not depend on the base enricher
2024-07-15T17:54:37+01:00: rename enrichment db migrations to deduplication-db-migrations to better reflect usage
**v0.19.0**
2024-07-15T17:28:37+01:00: remove postgresql as a dependency, close #249
2024-07-16T16:08:15+01:00: 🐛 Fix incorrect version for enrichment-db-migrations chart
2024-07-16T16:07:41+01:00: 🐛 Remove duplicate statement from Makefile
2024-07-11T14:49:23+01:00: ⬆️  Upgrade `vendor/` dependencies
2024-06-03T13:38:56+01:00: ♻️  Create base enricher
2024-07-10T18:38:35+01:00: 📝 Add warning to `enrichers/policy:README` about memory requirements
2024-07-10T18:35:17+01:00: 🔥 Remove `enricher-policy` from example pipelines2024-07-14T20:01:38+01:00: fix #247, push the right package to oci registry for enrichmentdb migrations
2024-07-14T19:40:26+01:00: actually fix #244 by setting the correct helm flags
2024-07-14T19:24:42+01:00: fix #244 by setting the correct helm flags
2024-07-12T16:56:19+01:00: split enrichment db migrations helm chart, close #2412024-07-05T18:27:27+01:00: 📝 Add README to `producer/semgrep`
2024-07-05T18:01:22+01:00: 🐛 Fix `producer/semgrep` not supporting registry
2024-07-02T09:53:59+01:00: [OCU-122] ✨ Add new `GetPURLTarget` method to base-producer (#213)2024-06-19T15:20:38+01:00: fix formatting of migrations and enum generating docs
2024-06-19T15:11:07+01:00: 225: push the draconctl image also with the latest tag
**v0.17.0**
2024-06-14T16:15:25+01:00: migrations specific documentation
2024-06-12T16:04:31+01:00: Move draconctl migrations apply <path> to environment variable
2024-06-14T14:15:51+01:00: #214 :wrench: Improve ComponentType and OrchestrationType enums (#221)2024-06-05T19:55:59+01:00: #203 add target for html coverage
2024-06-12T14:58:51+01:00: 🔨  Extend `Makefile` with new `generate-protos` command
**v0.16.0**
2024-06-12T14:03:02+01:00: 🚨 Run formatter
2024-06-12T14:01:54+01:00: 📝 Add docs on how to generate and update protos
2024-06-12T13:57:13+01:00: 🏷️ Generate updated go protobufs
2024-06-12T13:56:31+01:00: 👷 Add `buf.gen.yaml`
2024-06-12T13:56:06+01:00: ⬆️ Bump `buf@1.28.1->1.32.2`
2024-06-12T12:09:24+01:00: 🏷️ Extend `LaunchToolResponse` proto by new `scan_target` field
2024-06-12T11:39:59+01:00: bump braces node module (#216)2024-06-07T17:40:55+01:00: 🐛 Fix some producers failing if unable to extract code
2024-06-03T13:38:56+01:00: move constants to base component
**v0.15.0**
2024-06-03T12:06:32+01:00: add logging to base producers and consumers
2024-06-03T11:58:05+01:00: add structured dracon logging
2024-06-05T12:07:58+01:00: redirect reviewdog stderr to stdout2024-06-05T12:01:13+01:00: remove tee flag from reviewdog for reduced verbosity
2024-06-05T11:36:13+01:00: 197: commit objects to memory when fake K8s apply method is invoked
2024-06-05T11:34:50+01:00: current linter setup is very noisy, also reviewdog's github integration has a bug that double/tripple reports findings on removed code, however, when running locally, the linter works as expected, so we do the same for ci/cd
2024-06-04T12:23:06+01:00: 195: allow user to choose if they want a Kibana ingress to be deployed2024-06-03T14:21:04+01:00: make migrations job able to be deleted and recreated many times so that we can deploy multiple times
2024-06-03T17:06:17+01:00: add ref to 'missing reference' message
2024-05-21T17:39:25+01:00: 188: fix typo in make variable
**v0.13.0**
2024-05-21T17:39:25+01:00: 188: fix typo in make variable2024-05-21T13:49:41+01:00: expose component discovery methods for local components
2024-05-14T17:10:42+03:00: 183: cleanup all example pipelines
2024-05-14T16:45:53+03:00: nit: remove namespace from connection string for more flexibility
2024-05-13T23:37:10+03:00: 182: remove ensure_hashes script and helpers
2024-05-13T23:31:47+03:00: 182: remove leftover e2e and release scripts and BUILD files
2024-05-13T23:31:10+03:00: 182: remove tektoncd openapi resources and base transformer
2024-05-13T23:30:17+03:00: remove leftover make targets for generating pipelines
2024-05-14T19:40:58+03:00: update suggested version in docs to v0.13.0
**v0.12.0**
2024-05-14T19:33:13+03:00: 180: add dracon_scan_start_time, dracon_scan_id and dracon_scan_tags to producers2024-05-14T16:43:24+01:00: [OCU-106] clean example-pipelines-helm-manifests
2024-05-10T21:46:25+01:00: [OCU-102] fix custom package deployment instructions
2024-05-10T18:03:03+01:00: [OCU-103] fix bandit and safety extra docker containers
2024-05-13T14:27:33+01:00: 176: marshal ComponentType and OrchestrationType as string2024-05-08T18:03:23+01:00: fix 170: add more checks for unresolved components2024-05-07T19:03:43+01:00: cleanup golang project example, fix mongodb deployment and pipelinerun parameters
**v0.11.0**
2024-05-07T18:15:11+01:00: fix name of Helm package uploaded by publish action
**v0.10.0**
2024-05-07T18:02:11+01:00: fix buggy assignment of version flag when creating Helm component package
**v0.9.0**
2024-05-07T17:47:25+01:00: set component package version to original tag value
**v0.8.0**
2024-05-07T17:47:25+01:00: set component package version to original tag value2024-05-07T17:12:41+01:00: add missing namespace from dracon component deploying command
2024-05-07T17:06:00+01:00: deploy dracon-oss-components as part of dev-dracon make target
2024-05-07T16:52:02+01:00: typo fixes for make phony target and docs
2024-05-07T16:39:00+01:00: re-introduce dev-deploy target with updated dependencies
**v0.7.0**
2024-05-07T16:38:06+01:00: document new Dracon deployment workflows
2024-05-07T16:28:19+01:00: refactor dracon Helm chart folder2024-05-07T16:27:52+01:00: minor fmt fix in pkg/components/package_test.go
2024-05-07T15:41:38+01:00: publish all containers not just component containers
2024-05-07T13:53:07+01:00: fixes 169: programmatically pin component images to specific Dracon version
**v0.6.0**
2024-05-07T13:41:33+01:00: fixes 169: pin all components Tasks to latest version2024-05-07T13:17:30+01:00: remove hardcoded anchor from git-clone task2024-05-07T13:04:05+01:00: yeet even more kustomization.yamls
2024-05-07T11:34:33+01:00: improve docstring of Orchestrator interface
2024-05-06T10:38:14+03:00: fix path of Helm dracon oss chart
**v0.5.0**
2024-05-06T10:29:20+03:00: make tag format more explicit for publish action trigger
2024-05-06T08:40:16+03:00: fixes 168: label all container with org.opencontainers.image.source
**v0.4.0**
2024-05-06T00:17:56+03:00: fix permissions for publishing job
**v0.3.0**
2024-05-06T00:06:11+03:00: fixes 149: give permission to publish job to write packages
**v0.2.0**
2024-05-05T23:37:01+03:00: remove accidentally commited dummy test file

