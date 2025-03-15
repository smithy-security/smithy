# Unified Codeql Runner

This binary, and the container it is wrapped in, automatically detect the languages
in a repository tree and for every language prepare a codeql database and analyze it.

## Limitations

* codeql runs with build-mode = none unless the language is go where it runs with build-mode='autobuild'
* C and Cpp are not supported
* in the current configuration codeql command line args cannot be customized
