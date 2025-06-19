from .component import Component
from logging import Logger
from typing import Optional, Union
import uuid
from abc import abstractmethod
from smithy_python.enums.db_type_enum import DBTypeEnum

class Enricher(Component):
    """
    An enricher is a component in the Smithy Python SDK that represents an enricher in the smithy framework.
    Enrichers are used to add context or additional information to findings.
    """

    def __init__(self, instance_id: Union[uuid.UUID, str], db_type: DBTypeEnum, logger: Optional[Logger] = None) -> None:
        """
        Initializes a new instance of the Enricher class.
        :param instance_id: The UUID of the instance (aka the Workflow run to be analyzed)
        :type instance_id: Union[uuid.UUID, str]
        :param db_type: The database mode for the enricher, DBTypeEnum, can be either `SQLITE`, `POSTGRES` or `REMOTE`. (remote is gRPC)
        :type db_type: DBTypeEnum
        :param logger: An instance of the Logger class for logging. If not provided, a default logger will be used.
        :type logger: Optional[Logger]
        :raises ValueError: If the instance_id is not a valid UUID.
        :raises TypeError: If the instance_id is not a string or UUID object.
        :raises NotImplementedError: If the db_type is not `REMOTE`, as currently only `REMOTE` is supported.
        """

        super().__init__(instance_id, db_type, logger)
    
    @abstractmethod
    def enrich(self):
        """
        Enriches the findings in the database.
        This method should be implemented by subclasses to provide the enrichment logic.
        """
        
        # Retrieve findings from the database
        findings = self.db_manager.get_findings()
        
        # Do some enrichment logic here 
        raise NotImplementedError("This method should be implemented by subclasses.") # Remove this :D
        
        # Update findings in the database
        success = self.db_manager.update_findings(findings)
        if not success:
            self.log.error("Failed to update findings in the database.")
        return None