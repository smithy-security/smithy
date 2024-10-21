# Migrations

The project needs migrations since it has components that require a database.
Since we don't know how many components are installed on a smithy cluster and
how many of these components come with their own migrations or have any sort of
migrations at all.

To address this we created a generic way to apply migrations on demand as a job
in the cluster via smithyctl.

smithyctl has a `migrations` subcommand which can template and schedule a job
to run which contains migrations for a component.
The `migrationgs` subcommand requires:

* container image and tag which contain both `smithyctl` and the migrations
  `.sql` files
* path in the image where migrations are relative to `smithyctl`
* database connection string
* database table where migrations for this component will be tracked
