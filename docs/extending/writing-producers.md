# Writing Producers

A producer is a program that parses the output of a tool and converts it into
Smithy compatible output that can be used by *enrichers* and *consumers*.

***

Producers can be written in any language that supports protobufs. We currently
have examples in Golang and Python. They are all structured in the same way:

1. Parse program arguments:
   1. `in`: the raw tool results file location.
   2. `out`: where to place the Smithy compatible output file location.
2. Parse the `in` file into Protobufs (`LaunchToolResponse`).
3. Add metadata to Protobufs (e.g. git/source-code information).
4. Write the protobuf bytes to the `out` file.
5. Create a Tekton Task `task.yaml` with
   `.metadata.labels["v1.smithy.smithy-security.com/component"] = producer`.

## Producer API

For convenience, there are helper functions in the `./producers` pkg/module for
Golang/Python.

See the godoc for more information.
