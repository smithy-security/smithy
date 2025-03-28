# JAVA Dependency Check Producer

This producer is configured to be used specifically with the PURL ingestion
feature for Java.
It creates a minimal pom.xml out of the incoming dependency and its version and
proceeds to scan it with dependency check.

## Future improvements

Make this generic, a dedicated binary needs to create package manager specific
config and provide it.
