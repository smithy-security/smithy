# How we manage ENUM types

Currently, Go has inadequate support for ENUM types. This is why we generate
them with [abice/go-enum](https://github.com/abice/go-enum/tree/master).

## How

Go Enum can be run from a Docker container, so you don't need to install
anything locally. To generate a new type:

1. State your desired type in one of your files like so:

```go
// ComponentType represents all the types of components that Smithy supports
// ENUM(unknown, base, source, producer, producer-aggregator, enricher, enricher-aggregator, consumer)
type ComponentType string
```

2. Call go-enum on that file, with your required options. Note the package name
   in the end:

```bash
docker run -w /app -v $(pwd):/app abice/go-enum --file /app/pkg/components/mytypefile.go --marshal --mustparse --sqlnullstr --sql --names --values --noprefix -b mypackagename
```

1. This will generate a new file in that package called `mytypefile_enum.go`.
   That file will be owned by the Docker user, so you might want to reclaim it
   with `sudo chown $(whoami) mytypefile_enum.go`
2. If you want your IDE to recognize the new type, delete these lines from
   top of `mytypefile_enum.go`

```go
//go:build components
// +build components
```

## Examples

ENUMs that we have already generated with go-enum

* [/pkg/components/componenttype\_enum.go](https://github.com/smithy-security/smithy/blob/6da5a594328861fe09dea9570956276d5291215c/pkg/components/componenttype_enum.go)
  * ```bash
    docker run -w /app -v $(pwd):/app abice/go-enum --file /app/pkg/components/metadata.go --marshal --mustparse --sqlnullstr --sql --names --values --noprefix -b components 
    ```
* [/pkg/components/orchestrationtype\_enum.go](https://github.com/smithy-security/smithy/blob/8ba832b1cde7bac043d48eaf3401d6b9ea0ed275/pkg/components/orchestrationtype_enum.go)
  * ```bash
    docker run -w /app -v $(pwd):/app abice/go-enum --file /app/pkg/components/types.go --marshal --lower --ptr --mustparse --sqlnullstr --sql --names -b components
    ```
