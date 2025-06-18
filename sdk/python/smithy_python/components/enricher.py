from .component import Component
from smithy_python.helpers.logger import log
from logging import Logger
from typing import Optional

class Enricher(Component):
    """
    An enricher is a component in the Smithy Python SDK that represents an enricher in the smithy framework.
    Enrichers are used to add context or additional information to findings.
    """

    def __init__(self, instance_id: str, db_mode: str, logger: Optional[Logger] = None):
        """
        Initializes a new instance of the Enricher class.
        :param instance_id: The UUID of the enricher instance.
        :type instance_id: str
        :param db_mode: The database mode for the enricher, either `sqlite`, `postgres` or `remote`. (remote is gRPC)
        :type db_mode: str
        :param logger: An instance of the Logger class for logging. If not provided, a default logger will be used.
        :type logger: Optional[Logger]
        :raises ValueError: If the instance_id is not a valid UUID.
        :raises TypeError: If the instance_id is not a string or UUID object.
        :raises NotImplementedError: If the db_mode is not `remote`, as currently only `remote` is supported.
        """

        if not logger:
            logger = log

        super().__init__(instance_id, db_mode, logger)
    
    