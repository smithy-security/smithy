# Policy Enricher

Large (and small) teams would benefit from having a way to automatically make
decisions about scan results.
This would allow them to custom tag results based on logic evaluation making it
trivial to filter or otherwise manipulate results downstream.

## Requirements

As a user of this application I should be able to:

* Upload and manage a set of rules in some DSL
* Build policies in a user friendly way
* Have a set of example default policies available for testing
* Have Smithy apply the rules to the findings of a pipelinerun
* Get enriched results with information of which policies passed and which
  failed
* Control which policies apply to which pipeline

## Implementation

[OPA](https://www.openpolicyagent.org/) seems to be the leading policy engine
nowadays. It's datalog based DSL for defining rules is easy-ish to use by
developers and there are numerous integrations as well as widespread support
for technologies and plugins. We can use OPAs
[rego package](https://pkg.go.dev/github.com/open-policy-agent/opa/rego) to
integrate a lighweight Rego evaluator as an enricher.

This way, policies can live in a filesystem as rego files and be managed
accordingly. The benefits of this approach is that users are more likely to
already be familiar with Rego and then can use Styra's
[DAS](https://www.styra.com/press/styra-introduces-rego-policy-builder/)
offering to visually buld policies.

Minio is a convenient solution for a Rego file manager and it further allows for
matching policies to pipelines by copying the policy in a folder named after
the pipeline. Further, this enables the policy enricher to integrate with any
solution that supports the S3 API.

### API changes

Currently the API smithy uses supports only the following fields in a raw
finding:

```proto
// can be host:port or //foo/bar
string target = 1; 
// CWE-ID, etc for XSS, CSRF, etc.
string type = 2; 
// the vulnerability title from the tool
string title = 3; 
Severity severity = 4;
double cvss = 5;
Confidence confidence = 6;
// human readable description of the issue
string description = 7; 
// https://github.com/smithy-security/smithy.git?ref=<revision>, github.com:tektoncd/pipeline.git?ref=<revision>, local?ref=local
string source = 8; 
// [Optional] the CVE causing this vulnerability
string cve = 9; 
```

and in an enriched finding:

```proto
Is  sue raw_issue = 1;
// The first time this issue was seen by the enrichment service
google.protobuf.Timestamp first_seen = 2;
// The number of times this issue was seen
uint64 count = 3;
// Whether this issue has been previously marked as a false positive
bool false_positive = 4;
// The last time this issue was updated
google.protobuf.Timestamp updated_at = 5;
// hash
string hash = 6;
```

These do not support enough information for the enricher to add policy
information.
Thus the API will need to be extended with further fields. Due to the fact that
an unknown number of policies will need to be evaluated, it is suggested that
the following addition is made to the enriched finding message.

```proto
message EnrichedIssue {
  Issue raw_issue = 1;
  // The first time this issue was seen by the enrichment service
  google.protobuf.Timestamp first_seen = 2;
  // The number of times this issue was seen
  uint64 count = 3;
  // Whether this issue has been previously marked as a false positive
  bool false_positive = 4;
  // The last time this issue was updated
  google.protobuf.Timestamp updated_at = 5;
  // hash
  string hash = 6;

  map<string, string> annotations = 7;
}
```

This backwards compatible change allows smithy to optionally append policy
information to a message.

### Enricher execution changes

Having multiple enrichers run in parallel would currently break message
uniqueness. Current consumer design assumes that any finding corresponds to a
unique producer finding. If we have multiple enrichers run in parallel then we
will have finding dupication with different information appended to each
version of a finding based on which enricher ran on it. There are two suggested
ways of preserving finding uniqueness while having
multiple enrichers:

1. The enricher phase can run enrichers in series randomising their execution
   order. This would allow a quick and easy way of chaining a potentially large
   ammount of enrichers all while preserving finding uniqueness. However
   performance would suffer drastically.
2. The enricher phase can be pre-empted by a "message uniqueness" phase which
   adds a UUID to each enriched message. Then enrichers can then run in parallel
   , followed by an aggregation phase which generates new messages adding all
   the information from each enricher to the specific message UUID.
