.PHONY: pull-migrator-image new-postgres-migration update-postgres-migrations-sum new-sqlite-migration update-sqlite-migrations-sum

pull-migrator-image:
	docker pull --platform linux/amd64 arigaio/atlas:latest-alpine

new-postgres-migration: pull-migrator-image
	@if [ -z "$(migration_name)" ]; then \
		echo "Error: migration_name is not defined"; \
		exit 1; \
	fi
	docker run \
		--platform linux/amd64 \
		-v ./component/store/remote/postgresql/sqlc/migrations:/migrations \
		--rm \
		-it arigaio/atlas:latest-alpine \
		migrate \
		new $(migration_name) \
		--dir "file://migrations"

update-postgres-migrations-sum: pull-migrator-image
	docker run \
		--platform linux/amd64 \
		-v ./component/store/remote/postgresql/sqlc/migrations:/migrations \
		--rm \
		-it arigaio/atlas:latest-alpine \
		migrate \
		hash \
		--dir "file://migrations"

new-sqlite-migration: pull-migrator-image
	@if [ -z "$(migration_name)" ]; then \
		echo "Error: migration_name is not defined"; \
		exit 1; \
	fi
	docker run \
		--platform linux/amd64 \
		-v ./component/store/local/sqlite/sqlc/migrations:/migrations \
		--rm \
		-it arigaio/atlas:latest-alpine \
		migrate \
		new $(migration_name) \
		--dir "file://migrations"

update-sqlite-migrations-sum: pull-migrator-image
	docker run \
		--platform linux/amd64 \
		-v ./component/store/local/sqlite/sqlc/migrations:/migrations \
		--rm \
		-it arigaio/atlas:latest-alpine \
		migrate \
		hash \
		--dir "file://migrations"
