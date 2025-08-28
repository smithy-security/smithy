.PHONY: build-image generate-schemas

# Schema versions.
VERSIONS := v2-1-0 v2-2-0
# Base paths.
SPEC_DIR := spec/contracts/sarif-schema
GEN_DIR := gen/sarif-schema

build-image:
	@echo "Building the Docker image..."
	docker build \
		--platform linux/amd64 \
		-t gojsonschema . -f Dockerfile.gojsonschema

generate-schemas: build-image
	@for version in $(VERSIONS); do \
		echo "Generating schema for $$version..."; \
		rm -rf $(GEN_DIR)/$$version; \
		mkdir -p $(GEN_DIR)/$$version; \
		docker run \
			--platform linux/amd64 \
			-v ./spec:/app/spec \
			-it gojsonschema:latest \
			-p schema $(SPEC_DIR)/$$version/schema.json > $(GEN_DIR)/$$version/schema.go; \
	done