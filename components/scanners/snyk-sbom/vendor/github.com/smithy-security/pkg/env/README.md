# Env

Minimalistic package for environment variable lookup of type defined in `Parseable`.

## Example usage

```go
package main

import (
	"github.com/smithy-security/pkg/env"
)

func main() {
	// Will error if not defined or a valid integer.
	intVar, err := env.GetOrDefault("MY_INT_ENV_VAR", 10)
	if err != nil {
		...
    }

	// Will return the default value 10 if not defined or on error
	anotherIntVar, err := env.GetOrDefault("MY_OTHER_INT_ENV_VAR", 10, env.WithDefaultOnError(true))
	if err != nil {
		...
	}
}
```

## On testing

Customise `Loader` to mock your environment. Check the examples in `env_test.go`.
