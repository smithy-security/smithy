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
poetry add smithy
```

## Usage

### Basic Enricher Implementation

Create a custom enricher by extending the `Enricher` base class:

```python
import uuid
from logging import Logger
from typing import Union, Optional

from smithy.components.enricher import Enricher
from smithy.enums.db_type_enum import DBTypeEnum


class ExampleEnricher(Enricher):
    """
    A class that enrich
    findings with annotations.
    This class extends the Enricher class and provides a method to annotate findings.
    """

    def __init__(
        self,
        instance_id: Union[uuid.UUID, str],
        db_type: DBTypeEnum,
        logger: Optional[Logger] = None,
    ) -> None:
        """
        Initializes a new instance of the ExampleEnricher class.
        :param instance_id: The UUID of the instance (aka the Workflow run to be analyzed)
        :type instance_id: Union[uuid.UUID, str]
        :param db_type: The database mode for the enricher, DBTypeEnum, can be either `SQLITE`, `POSTGRES` or `REMOTE`. (remote is gRPC)
        :type db_type: DBTypeEnum
        :param logger: An instance of the Logger class for logging. If not provided, a default logger will be used.
        :type logger: Optional[Logger]
        """

        super().__init__(instance_id, db_type, logger)

    def enrich(self):
        """
        Enriches the findings in the database with annotations.
        This method retrieves findings from the database and adds annotations to them.
        The actual annotation logic should be implemented in this method.
        """

        # Retrieve findings from the database
        findings = self.db_manager.get_findings()
        annotated_findings = []

        # Iterate over findings and annotate them
        for finding in findings:
            # Here you would implement the logic to annotate each finding
            # For example, adding metadata or additional context
            finding.details.comment = "This is an annotated finding."
            annotated_findings.append(finding)

        # Update findings in the database with annotations
        self.db_manager.update_findings(annotated_findings)
```

### Using EnricherContext for Batch Processing

For efficient processing of large datasets, use the `EnricherContext` context manager:

```python
from smithy.components.enricher_context import EnricherContext
from smithy.enums.db_type_enum import DBTypeEnum


def process_functions():
    """
    function to demonstrate the usage of EnricherContext.
    """

    with EnricherContext(
        instance_id="cb5830f7-306a-49cf-ad11-cf31270c6751", db_type=DBTypeEnum.REMOTE
    ) as context:
        for finding in context:
            # print(f"Finding ID: {finding.id}, Details: {finding.details}")
            finding.details.comment = "This is a test comment."
            context.update(finding)


if __name__ == "__main__":
    process_functions()
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
