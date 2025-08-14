# Smithy Python SDK

The Smithy Python SDK is a library that provides a Python interface for developing Smithy components, currently **ONLY** Enrichers, but soon also Filters, Targets, Scanners and Reporters. This SDK enables you to build custom components that integrate with the Smithy workflow engine. (Learn more about [Smithy](https://smithy.security/)).

## What This Library Does

The Smithy Python SDK provides:

* **Enricher Components**: Base classes and utilities for creating custom enrichers that add context to security findings
* **Database Management**: Abstracted database operations for storing and retrieving findings
* **Context Management**: Iterator-based context managers for efficient batch processing of findings
* **gRPC Integration**: Built-in support for remote database operations via gRPC

## Current Implementation Status

### ✅ Fully Implemented Components

* **Enrichers**: Complete implementation with base classes, context managers, and examples

### ❌ Not Yet Implemented Components

* **Scanners**: Not implemented in Python SDK
* **Filters**: Not implemented in Python SDK
* **Targets**: Not implemented in Python SDK
* **Reporters**: Not implemented in Python SDK

### Database Handler Status

* **Remote (gRPC)**: ✅ Fully implemented and supported
* **PostgreSQL**: ❌ Interface defined but not implemented (`NotImplementedError`)
* **SQLite**: ❌ Interface defined but not implemented (`NotImplementedError`)

> **ATTENTION**: Currently, only the `REMOTE` database type (gRPC) is functional. Using `POSTGRES` or `SQLITE` will raise a `NotImplementedError`.

## 🛠️ Installation

Install the Smithy Python SDK using Poetry:

```bash
poetry add "git+https://github.com/smithy-security/smithy.git@main#subdirectory=sdk/python"
```

or add it using `pip`:

```bash
pip install "git+https://github.com/smithy-security/smithy.git@main#subdirectory=sdk/python"
```

We recommend using a tagged version instead of just checking out the `main` branch.
As GitHub does not support search/filter functionality for tags natively, you can list all sdk related tags using the following command:

```bash
git ls-remote --tags --refs https://github.com/smithy-security/smithy.git 'refs/tags/sdk/*'
```

This will list all the tags that start with `sdk/`. You can then choose the latest tag that fits your needs and use it in the installation command.

Alternatively, you can use the following snippet to automatically sort for and use the latest tag:

```bash
latest_tag=$(                           
  git ls-remote --tags --refs https://github.com/smithy-security/smithy.git 'refs/tags/sdk/*' |
  cut -f2 |
  sed 's#refs/tags/##' |
  sort -V | tail -n1
)
poetry add "git+https://github.com/smithy-security/smithy.git@$latest_tag#subdirectory=sdk/python"
```

(exchange `poetry add` with `pip install` if you prefer pip)

## Usage

To use the SDK you first need to create a Class inheriting from the component-type you want to have. In this example we will create a custom enricher by extending the `Enricher` base class then pass your enricher to the `Runner` which will execute it and handle the database operations.

For the following example we will recreate the existing `ExploitExistsEnricher` which adds an enrichment to findings indicating whether an exploit exists for a given vulnerability or not.

We will refrain from implementing the actual logic of checking for exploits, but instead focus on the structure of the enricher and how to properly annotate findings.

```python
from logging import Logger
from typing import Union, Optional, override

from google.protobuf import json_format

from smithy import Enricher
from smithy import Runner
from smithy import DBTypeEnum
from smithy import findings_service
from smithy import ocsf_ext
from smithy import ocsf_schema


class ExploitExistsEnricher(Enricher):
    """
    A class that enriches
    findings with annotations indicating whether Exploits exists.
    This class extends the Enricher class and provides a method to annotate findings.
    """

    def __init__(
        logger: Optional[Logger] = None,
    ) -> None:
        """
        Initializes a new instance of the ExploitsExistsEnricher class.
        :param logger: An instance of the Logger class for logging. If not provided, a default logger will be used.
        :type logger: Optional[Logger]
        """

        super().__init__(logger)

    @override
    def enrich(self, finding: findings_service.Finding) -> findings_service.Finding:
        """
        Enriches the findings in the database with annotations.
        This method gets findings from the database and adds annotations to them.
        The actual annotation logic should be implemented in this method.
        """

        exploit_exists_enrichment = ocsf_ext.Enrichment.ExploitsExistsEnrichment(
            exploit_url = "https://www.exploit-db.com/exploits/",  # Example URL, replace with actual logic
            references = ["CVE-2023-12345", "CVE-2023-67890"],  # Example CVEs, replace with actual logic
            is_exploitable = True,  # Example value, replace with actual logic
        )

        enrichment_str: str = json_format.MessageToJson(
            exploit_exists_enrichment,
            preserving_proto_field_name=True,
            including_default_value_fields=False,
            indent=None
        )
        
        finding.details.enrichments.append(
            ocsf_schema.Enrichment(
                name = "Exploit Exists Enrichment", # Optional
                provider = "ExploitsExistsEnricher", # Optional
                type = str(ocsf_ext.Enrichment.EnrichmentType.ENRICHMENT_TYPE_EXPLOIT_EXISTS), # Optional
                value = enrichment_str,
            )
        )

        return finding

def main():
    enricher = ExploitExistsEnricher()
    instance_id = "cb5830f7-306a-49cf-ad11-cf31270c6751"
    runner = Runner(
        component=enricher,
        instance_id=instance_id,
        db_type=DBTypeEnum.REMOTE,
    )
    runner.run()

if __name__ == "__main__":
    main()
```

## Configuration

### Database Configuration

Currently, only the remote gRPC database is supported. Configure your connection using environment variables:

```bash
export SMITHY_REMOTE_STORE_FINDINGS_SERVICE_ADDR="your-grpc-server:50051"  # Default: localhost:50051
export SMITHY_REMOTE_CLIENT_PAGE_SIZE="100"  # Optional: default is 100
export SMITHY_REMOTE_CLIENT_MAX_ATTEMPTS="10"  # Optional: default is 10
export SMITHY_REMOTE_CLIENT_INITIAL_BACKOFF_SECONDS="5s"  # Optional: default is 5s
export SMITHY_REMOTE_CLIENT_MAX_BACKOFF_SECONDS="60s"  # Optional: default is 60s
export SMITHY_REMOTE_CLIENT_BACKOFF_MULTIPLIER="1.5"  # Optional: default is 1.5
```

### Database Types

```python
from smithy.enums.db_type_enum import DBTypeEnum

# Available options (only REMOTE is currently functional)
DBTypeEnum.REMOTE    # ✅ gRPC connection to remote Smithy server
DBTypeEnum.POSTGRES  # ❌ Not implemented yet
DBTypeEnum.SQLITE    # ❌ Not implemented yet
```

## Testing, Formatting and Linting

#### Run the test suite:

**with `make`**:

```bash
make py-tests
```

**with `poetry` & `pytest`**:
(in the `sdk/python` directory)

```bash
poetry install --with dev
poetry run pytest
```

#### Lint the code:

```bash
make py-lint
```

#### Format the code:

(in the `sdk/python` directory)

```bash
poetry run black smithy/
```

(folders are excluded via `pyproject.toml`)

or

```bash
make fmt-py
```
