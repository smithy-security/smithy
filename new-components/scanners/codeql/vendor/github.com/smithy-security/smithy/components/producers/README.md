# Producers

A producer is a program that parses the output of a tool and converts it into
Smithy compatible file that can be used by the *enrichers* and *consumers*.

## Writing Producers

Producers can be written in any language that supports protobufs, we have
examples in Golang and Python. They are all structured the same way:

1. Parse program arguments:
   1. `in`: the raw tool results file location
   2. `out`: where to place the Smithy compatible output file location
2. Parse the `in` file into Protobufs (`LaunchToolResponse`)
3. Add metadata to Protobufs (e.g. git/source-code information)
4. Write the protobuf bytes to the `out` file

## Producer API

For convenience, there are helper functions in the `./producers` pkg/module for
Golang/Python.

The `WriteSmithyOut`/`write_smithy_out` method expects a list of issues to write
as the `LaunchToolResponse` protobuf. Your producer should parse the output of
a tool results into `Issue` protobufs which are then passed into this method.
