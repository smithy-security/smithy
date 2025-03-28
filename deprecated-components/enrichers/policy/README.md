# Policy Enricher

> **Warning:** This component has a memory limit of 5GB assigned to one of
> it's dependencies. Make sure you provide sufficient resources when running it.
>
> For example, Docker Desktop by default only allocates 2GB to itself. You
> MUST increase that limit manually in `Docker Desktop > Settings > Resources`
> if you want to run this component locally.

This enricher implements an MVP of the design outlined in
[the enricher design document](/docs/designs/policy-enricher.md).
In its current state it evaluates the `allow` rule of a single policy found
under the `policy_path` variable.

## Future steps

When/If there is interest around the policy enricher it should be modified to
work with an s3 compatible API and load policies more efficiently based on
either tool name or pipeline name.
