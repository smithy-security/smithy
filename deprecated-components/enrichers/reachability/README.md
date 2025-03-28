# Reachability

This enricher performs reachability analysis
using [atom](https://github.com/AppThreat/atom).

It enriches the raw results in input, for example
`bandit.tagged.pb` with a reachability tag.

The enricher requires `enricher-reachability-programming-language`
to be set as the mechanism to generate the
reports are different based on programming language.

## Environment variables

* `READ_PATH`: specifies the location from where to look for raw reports.
* `WRITE_PATH`: specifies the location where to write enriched results.
* `ATOM_FILE_PATH`: specifies the location where to find
  the atom file with a reachability report.

## Limitations

* Right now the enricher requires a file called `bom.json`
  to be produced by [cdxgen](https://github.com/CycloneDX/cdxgen)
  to be present in the directory where the cloned repository
  is located.

## Examples

Please check out [this example](../../../examples/pipelines/reachability-project)
to see the component in action!
