# git-clone

This is component implements a [target](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go#L55)
that clones repositories to the filesystem.

## Environment variables

The component used environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable      | Type   | Required | Default           | Description                                        |
|---------------------------|--------|----------|-------------------|----------------------------------------------------|
| GIT\_CLONE\_REPO\_URL        | string | yes      | -                 | Valid URL of the repository to clone               |
| GIT\_CLONE\_BRANCH\_NAME     | string | yes      | -                 | Valid branch name of the repository to clone       |
| GIT\_CLONE\_AUTH\_ENABLED    | bool   | no       | false             | Whether authentication should be used for VCS      |
| GIT\_CLONE\_ACCESS\_TOKEN    | string | no       | -                 | Access token to be leveraged for authentication    |
| GIT\_CLONE\_ACCESS\_USERNAME | string | no       | -                 | Access username to be leveraged for authentication |

## build git-clone

```shell
make build-target
```

## How to run

## git-clone and gitea

Spins up [gitea](https://about.gitea.com/) locally and the `git-clone` component.

```shell
make run
```

## git-clone, gitea and seeder

Like above but also seeding `gitea` with a sample repository that `git-clone` can clone out of the box.

```shell
make run-with-seeder
```

## shutdown

```shell
make shutdown
```
