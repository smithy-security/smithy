# SDK

Smithy's SDK.

## Component

The component package can be used to write Smithy
components that represents
Vulnerability Findings data in [OCSF](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html) format.

OCSF is a standard for representing vulnerability reports that can be understood by a variety of
security tools.

This package allows you to focus on writing the business logic for your component
while taking care of the boring things for you:

* running the components steps in a predictable and reliable way
* deal with persisting and updating findings data in an underlying storage
* handle intricacies like cancellations and graceful shutdown
* taking care of logging and panic handling
* reporting common metrics to track what your component is doing

You can customise a component using the following environment variables:

| Environment Variable                | Type   | Required | Default                  | Possible Values                     |
|-------------------------------------|--------|----------|--------------------------|-------------------------------------|
| SMITHY\_COMPONENT\_NAME             | string | yes      | -                        | -                                   |
| SMITHY\_LOG\_LEVEL                  | string | false    | info, debug, warn, error |
| SMITHY\_STORE\_TYPE                  | string | no       | sqlite                   | sqlite, postgresql, findings-client |

`Runners` can be supplied with `RunnerConfigOption`s to customise how a component runs.
In the following example you can see how we change the component name:

```go
component.RunTarget(
	ctx, 
	sampleTarget{}, 
	component.RunnerWithComponentName("sample-target"),
)
```

For local development, a default `SQLite` Backend Store Type will be used. This can be customised with:

```go
component.RunTarget(
	ctx, 
	sampleTarget{}, 
	component.RunnerWithStorer(//a storer),
)
```

### Components

#### Target

A `Target` component should be used to prepare a target for scanning.

For example, cloning a repository and make it available for a `Scanner` to scan.
A `git-clone` component is an example of a `Target`.

You can create a new `Target` component like follows:

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
)

type sampleTarget struct{}

func (s sampleTarget) Prepare(ctx context.Context) error {
	// Prepare the target here!
	// This is the main execution method of the Target component type. 
	// Here you need to implement your logic.
	// For example for a target component that clones a repository here is where you 
	// setup your arguments and call git clone.
	return nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunTarget(ctx, sampleTarget{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
```

#### Scanner

A `Scanner` scans a `Target` to find vulnerabilities.

`Go-Sec` component is an example of a scanner component.

You can create a new `Scanner` component like follows:

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type sampleScanner struct{}

func (s sampleScanner) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	// Transform your payload to ocsf format here!
	// Read raw findings prepared by a Target and transform them to a format that makes sense!
	return make([]*ocsf.VulnerabilityFinding, 0, 10), nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunScanner(ctx, sampleScanner{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
```

#### Enricher

An `Enricher` annotates vulnerability findings with extra information.

`Deduplication` component is an example `Enricher`.

You can create a new `Enricher` component like follows:

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type sampleEnricher struct{}

func (s sampleEnricher) Annotate(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
	// Enrich your vulnerability findings here!
	// Make sense of you vulnerability data and add enriching annotations to take smarter decisions.
	return make([]*ocsf.VulnerabilityFinding, 0, 10), nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunEnricher(ctx, sampleEnricher{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
```

#### Filter

A `Filter` component allows to filter out some vulnerability findings based on
arbitrary criteria.

For example, you might want to filter out vulnerabilities on a specific path in a repository.

You can create a new `Filter` component like follows:

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type sampleFilter struct{}

func (s sampleFilter) Filter(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, bool, error) {
	// Filter out your vulnerability findings here!
	// Remove the noise from your pipeline and ignore findings based on a supplied criteria.
	return make([]*ocsf.VulnerabilityFinding, 0, 80), true, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunFilter(ctx, sampleFilter{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
```

#### Reporter

A `Reporter` component allows you to report vulnerabilities on your favourite
destination.

For example, report each one of them as ticket on a ticketing system or dump
them into a data lake. `Slack` is an example `Reporter`.

You can create a new `Reporter` component like follows:

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type sampleReporter struct{}

func (s sampleReporter) Report(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	// Report your vulnerability findings here.
	// Raise them as tickets on Jira or post a message on Slack here!
	return nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := component.RunReporter(ctx, sampleReporter{}); err != nil {
		log.Fatalf("unexpected run error: %v", err)
	}
}
```

### Utilities

#### Logging

`component` makes it easy for you to leverage the default logger in your business logic.

You can access the logger anytime using `component.LoggerFromContext(ctx)`.

For example:

```go
func (s sampleEnricher) Update(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	component.LoggerFromContext(ctx).Info("Preparing to update findings")
	return nil
}
```

You can also customise the logger if you wish:

```go
type noopLogger struct {}

func (n *noopLogger) Debug(msg string, keyvals ...any) {}
func (n *noopLogger) Info(msg string, keyvals ...any)  {}
func (n *noopLogger) Warn(msg string, keyvals ...any)  {}
func (n *noopLogger) Error(msg string, keyvals ...any) {}
func (n *noopLogger) With(args ...any) Logger {
    return &noopLogger{}
}

...

logger := noopLogger{}

if err := component.RunReporter(
	ctx, 
	sampleReporter{}, 
	component.RunnerWithLogger(logger),
); err != nil {
    log.Fatalf("unexpected run error: %v", err)
}
```

### Storages

Smithy SDK allows to configure different storages to boost adoption.

By default, [sqlite](https://www.sqlite.org/) is used for local development.

#### Postgresql

You can configure a Postgresql storage by plugging in `/store/remote/postgresql` or configuring the required
environment variables defined in its README.

#### Findings Client

You can configure a grpc findings client storage by plugging in `/store/remote/findings-client` or configuring the required
environment variables defined in its README.

#### Custom

You can supply your own implementation of a storage by satisfying the `componenent.Storer` interface and leveraging the
`RunnerWithStorer` option.

### Contributing

#### Database Schemas

They are generated using [sqlc](https://sqlc.dev/) from real SQL schemas and queries.

##### Generation

You can generate types mapping schemas and queries by leveraging the `go:generate` entries in `tools.go`.

#### Migrations

Components require a common database/tables setup to function properly.

This is achieved with migrations.

##### SQLite

Postgresql migrations live in `./component/store/local/sqlc/sqlc/migrations`.

In order to create a new migration, you can follow these steps:

* run `$ make new-sqlite-migration migration_name=my_migration`
* edit the migration
* run `$ update-sqlite-migrations-sum` to update `atlas.sum`

##### Postgresql

Postgresql migrations live in `./component/store/remote/postgresql/sqlc/migrations`.

In order to create a new migration, you can follow these steps:

* run `$ make new-postgres-migration migration_name=my_migration`
* edit the migration
* run `$ update-postgres-migrations-sum` to update `atlas.sum`
