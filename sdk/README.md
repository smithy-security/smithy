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
* handle intricacies like cancellations and graceful shutdown
* taking care of logging and panic handling
* reporting common metrics to track what your component is doing

You can customise a component using the following environment variables:

| Environment Variable       | Type   | Required | Possible Values                |
|----------------------------|--------|----------|--------------------------------|
| SMITHY\_COMPONENT\_NAME       | string | yes      | -                              |
| SMITHY\_LOGGING\_LOG\_LEVEL    | string | false    | info, debug, warn, error       |

Or you can use the supplied options `RunOption`, like in this example:

```go
component.RunTarget(
	ctx, 
	sampleTarget{}, 
	component.RunnerWithComponentName("sample-target"),
)
```

### Components

#### Target

A `Target` component should be used to prepare a target for scanning.

For example, cloning a repository and make it available for a `Scanner` to scan.

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

func (s sampleTarget) Close(ctx context.Context) error {
	// Close your component here!
	return nil
}

func (s sampleTarget) Prepare(ctx context.Context) error {
	// Prepare the target here!
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

type (
	sampleScanner struct{}

	sampleRawVuln struct{}
)

func (s sampleRawVuln) Unmarshal() (*ocsf.VulnerabilityFinding, error) {
	// Tell us how to convert your payload to ocsf format here!
	return &ocsf.VulnerabilityFinding{}, nil
}

func (s sampleScanner) Close(ctx context.Context) error {
	// Close your component here!
	return nil
}

func (s sampleScanner) Store(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	// Store your findings here!
	return nil
}

func (s sampleScanner) Scan(ctx context.Context) ([]component.Unmarshaler, error) {
	// Scan a target and return a payload here!
	return nil, nil
}

func (s sampleScanner) Transform(ctx context.Context, payload component.Unmarshaler) (*ocsf.VulnerabilityFinding, error) {
	// Transform your payload to ocsf format!
	return &ocsf.VulnerabilityFinding{}, nil
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

func (s sampleEnricher) Close(ctx context.Context) error {
	// Close your component here!
	return nil
}

func (s sampleEnricher) Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	// Read the prepared vulnerability reports here.
	return make([]*ocsf.VulnerabilityFinding, 0, 10), nil
}

func (s sampleEnricher) Update(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	// Update your vulnerability findings here.
	return nil
}

func (s sampleEnricher) Annotate(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, error) {
	// Enrich your vulnerability findings here.
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

func (s sampleFilter) Close(ctx context.Context) error {
	// Close your component here!
    return nil
}

func (s sampleFilter) Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	// Read the prepared vulnerability reports here.
	return make([]*ocsf.VulnerabilityFinding, 0, 100), nil
}

func (s sampleFilter) Update(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	// Update your vulnerability findings here.
	return nil
}

func (s sampleFilter) Filter(ctx context.Context, findings []*ocsf.VulnerabilityFinding) ([]*ocsf.VulnerabilityFinding, bool, error) {
	// Filter out your vulnerability findings here.
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
them into a data lake.

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

func (s sampleReporter) Close(ctx context.Context) error {
	// Close your component here!
	return nil
}

func (s sampleReporter) Read(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	// Read the prepared vulnerability reports here.
	return make([]*ocsf.VulnerabilityFinding, 0, 100), nil
}

func (s sampleReporter) Report(ctx context.Context, findings []*ocsf.VulnerabilityFinding) error {
	// Report your vulnerability findings here.
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
