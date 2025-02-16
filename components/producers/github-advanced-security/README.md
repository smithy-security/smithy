# Producer: GitHub Code Scanning

<!--lint disable maximum-line-length-->

This producer [queries the GitHub Code Scanning API](https://docs.github.com/en/rest/code-scanning/code-scanning?apiVersion=2022-11-28#list-code-scanning-alerts-for-a-repository) to produce SAST findings.

## Parameters

All parameters are **required**.

| Name                                             | Type     | Default | Description                                                                                                                                                                                                                                              |
| ------------------------------------------------ | -------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `producer-github-code-scanning-repository-owner` | `string` | N/A     | The owner of the repository to scan.                                                                                                                                                                                                                     |
| `producer-github-code-scanning-repository-name`  | `string` | N/A     | The name of the repository to scan.                                                                                                                                                                                                                      |
| `producer-github-code-scanning-github-token`     | `string` | N/A     | The GitHub token to use for scanning. Must have "Code scanning alerts" repository permissions (read) ([More Information](https://docs.github.com/en/rest/code-scanning/code-scanning?apiVersion=2022-11-28#list-code-scanning-alerts-for-a-repository)). |

<!--lint enable maximum-line-length-->
