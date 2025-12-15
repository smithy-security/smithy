# 1.1.0 (October 2, 2024)

* The YAML decoder now exactly follows the [YAML specification](https://yaml.org/spec/1.2-old/spec.html#id2805071) when resolving the implied YAML tags for integers. ([#6](https://github.com/zclconf/go-cty-yaml/pull/6))

    The new implementation matches the patterns in the specification, but it now has stricter integer resolution than the previous release. The primary goal of this library is to translate valid YAML syntax to and from `cty`'s type system and so deviation from the YAML grammar is treated typically as a bug to be fixed even if that means a change in behavior for existing callers that were dealing in invalid input. This further improves earlier work done in v1.0.2, which didn't quite match the spec.

    In particular:

    - Scalars containing underscores can no longer be resolved as integers.
    - Octal and hexadecimal sequences must now start with exactly `Oo` and `0x` respectively to be resolved as integers; a leading sign (`+` or `-`) is accepted only for the decimal integer and float patterns.

    The YAML tag resolution process infers an implied type tag for each scalar value that isn't explicitly tagged. `go-cty-yaml` then uses the YAML tags (whether implied or explicit) to decide which `cty` type to use for each value in the result.

    The scalar values that are no longer resolved as numbers will now all be resolved as strings instead, and so calling applications can perform further parsing and transformation on the resulting strings to accept forms outside of those in the YAML specification, if required.

# 1.0.3 (November 2, 2022)

* The `YAMLDecodeFunc` cty function now correctly handles both entirely empty
  documents and explicit top-level nulls. Previously it would always return
  an unknown value in those cases; it now returns a null value as intended.
  ([#7](https://github.com/zclconf/go-cty-yaml/pull/7))

# 1.0.2 (June 17, 2020)

* The YAML decoder now follows the YAML specification more closely when parsing
  numeric values.
  ([#6](https://github.com/zclconf/go-cty-yaml/pull/6))

# 1.0.1 (July 30, 2019)

* The YAML decoder is now correctly treating quoted scalars as verbatim literal
  strings rather than using the fuzzy type selection rules for them. Fuzzy
  type selection rules still apply to unquoted scalars.
  ([#4](https://github.com/zclconf/go-cty-yaml/pull/4))

# 1.0.0 (May 26, 2019)

Initial release.
