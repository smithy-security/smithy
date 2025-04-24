# Severity Filter

This component implements a [filter component](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
This filter accepts a minimum Severity and adds a "Filtered" enrichment to all findings that don't have at least the min severity.
This component does not care about the severity of each individual vulnerability, it only matches on the Finding Severity.
