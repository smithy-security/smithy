from smithy_python.components.enricher import Enricher
from smithy_python.enums.db_type_enum import DBTypeEnum
from logging import Logger
from typing import Union, Optional
import uuid

class ExampleEnricher(Enricher):
    """
    A class that enrich
    findings with annotations.
    This class extends the Enricher class and provides a method to annotate findings.
    """

    def __init__(self, instance_id: Union[uuid.UUID, str], db_type: DBTypeEnum, logger: Optional[Logger] = None) -> None:
        """
        Initializes a new instance of the AnnotateEnricher class.
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
            annotated_findings.append(finding)
        
        # Update findings in the database with annotations
        self.db_manager.update_findings(annotated_findings)