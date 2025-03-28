# Producer: Semgrep

<!--lint disable maximum-line-length-->

This producer runs [the Semgrep CLI](https://semgrep.dev/docs/cli-reference) to produce SAST findings.

## Parameters

All parameters are optional. The producer works with the default configuration and uses the `"auto"` ruleset.

| Name                            | Type     | Default       | Description                                                                            |
| ------------------------------- | -------- | ------------- | -------------------------------------------------------------------------------------- |
| `producer-semgrep-config-value` | `string` | `"auto"`      | The config for the Semgrep producer. Passed directly to the CLI via `--config`         |
| `producer-semgrep-rules-yaml`   | `string` | `"rules: []"` | Additional rules passed to Semgrep https://semgrep.dev/docs/writing-rules/rule-syntax. |

<!--lint enable maximum-line-length-->
