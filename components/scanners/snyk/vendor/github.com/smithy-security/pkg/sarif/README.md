# sarif

Utilities for [sarif](https://sarifweb.azurewebsites.net/) that leverage generated code for 
[sarif-spec](https://github.com/oasis-tcs/sarif-spec/tree/main).

## Why?

Other packages are not well maintained and don't leverage generated code.

This means that updates to the specification are not often backported into the packages.

## How to use

### V2.1.0
For [v2.1.0](https://github.com/oasis-tcs/sarif-spec/tree/main/sarif-2.1):

```go
package main

import (
	"log"

	schemav1 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
)

//go:embed testdata/gosec_v2.1.0.json
var reportV2_1_0 []byte

func main() {
	report := schemav1.SchemaJson{}
	if err := report.UnmarshalJSON(reportV2_1_0); err != nil {
		log.Fatalf("report unmarshalling failed: %v", err)
	}
}
```

### V2.2.0
For [v2.2.0](https://github.com/oasis-tcs/sarif-spec/tree/main/sarif-2.2):

```go
package main

import (
	"log"

	schemav2 "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-2-0"
)

//go:embed testdata/gosec_v2.2.0.json
var reportV2_2_0 []byte

func main() {
	report := schemav2.SchemaJson{}
	if err := report.UnmarshalJSON(reportV2_2_0); err != nil {
		log.Fatalf("report unmarshalling failed: %v", err)
	}
}
```

## Generate code

To generate the code from the jsonschema specs, please run:

```shell
make generate-schemas
```