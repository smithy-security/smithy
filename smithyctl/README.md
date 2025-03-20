# Smithyctl

Smithyctl is the CLI used to develop new components, run them in workflows and distributing them.

## Installation

```shell
go install github.com/smithy-security/smithy/smithyctl@latest
```

Verify installation by running:

```shell
smithyctl version
```

## Flags

| Flag          | Description                                                                 | Default   |
|---------------|-----------------------------------------------------------------------------|-----------|
| `debug-enabled` | enabled debug logs.                                                         | `false`     |
| `debug-level`   | sets the log level. Possible values `debug`, `info`, `warning` and `error`. | `debug`   |

## Commands

| Command     | Description                                                 | Status                |
|-------------|-------------------------------------------------------------|-----------------------|
| `help`      | will output how to use `smithyctl`                          | Implemented           |
| `version`   | will output the version of the installed `smithyctl` binary | Not implemented yet   |
| `component` | allows to develop, run and distribute components            | Not fully implemented |
| `workflow`  | allows to develop and run workflows                         | Implemented           |

### Component

* [packaging](./docs/component/PACKAGING.md): distributes a component specified in a [component.yaml](./docs/component/SPEC.md)
* [build](./docs/component/BUILD.md): allows to build component images.

### Workflow

* [run](./docs/workflow/RUN.md): runs components specified in a [workflow.yaml](./docs/workflow/SPEC.md)

## Development

Compile `smithyctl` locally by running `make smithyctl/bin` in the root of this project.

You can then find the binary in `./bin/smithyctl/cmd/{GOOS}/{GOARCH}/smithyctl`.
