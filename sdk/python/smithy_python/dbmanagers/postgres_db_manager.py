from typing import List, override, Union, Optional
from logging import Logger
from smithy_python.dbmanagers.db_manager import DBManager

class PostgresDBManager(DBManager):
    """
    A class to manage PostgreSQL database connections and operations.
    """

    def __init__(self, instance_id: str, logger: Optional[Logger] = None) -> None:
        """
        Initializes the PostgreSQL database manager with the given configuration.

        :param instance_id: The UUID of the instance (aka the Workflow run to be analyzed)
        :type instance_id: str
        :param logger: An instance of the Logger class for logging. If not provided, a default logger will be used.
        :type logger: Optional[Logger]
        :raises TypeError: If the logger is not an instance of Logger or None.
        """

        super().__init__(instance_id, logger)

        raise NotImplementedError("PostgresDBManager is not yet implemented.")


    @override
    def get_findings(self) -> List[any]:
        """
        Retrieves **all** findings from the postgres database which are associated to the class variable `instance_id`.
    
        :return: A list of findings retrieved from the postgres database.
        """

        pass

        
    def __del__(self):
        """
        Cleans up the PostgresDBManager instance.
        """

        super().__del__()