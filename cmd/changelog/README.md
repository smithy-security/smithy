# Changelog Section Generator

This binary is pointed to a repository and it generates a changelog based on the commit messages
between the latest tag and HEAD.

## Use Cases

### Tag first, then generate Changelog

If a user tags HEAD first then calls this binary, latest tag will point to the HEAD commit.
If HEAD and latest tag point to the same commit. The binary will produce a changelog for the previous tag and HEAD.

### Generate Changelog then tag

The default mode for this project is to run it before you tag a commit.
In this case you need to provide the name of the new tag and the message of the new tag in order to generate a correct changelog entry.
