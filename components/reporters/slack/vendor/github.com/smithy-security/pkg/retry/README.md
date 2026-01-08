# retry

Simple retry package to get a retryable `*http.Client` or `http.RoundTripper` 
that wraps [github.com/cenkalti/backoff/v5](github.com/cenkalti/backoff/v5).

## How to use

You can customise `retry.Config` as documented.

### Retryable `http.Client`

```go
import (
    "github.com/smithy-security/pkg/retry"
)

...

client, err := retry.NewClient(retry.Config{
	MaxRetries: 10,
})
...
```

### Retryable `http.RoundTripper`

```go
import (
    "github.com/smithy-security/pkg/retry"
)

...

rt, err := retry.NewRoundTripper(retry.Config{
	MaxRetries: 10,
})
...
```