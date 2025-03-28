# CodeOwners Enricher

This enricher scans the cloned source for
[CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
files, For each finding, it adds the following annotation.
"Owner-$incremental\_number:$the\_username\_of\_the\_owner>"
