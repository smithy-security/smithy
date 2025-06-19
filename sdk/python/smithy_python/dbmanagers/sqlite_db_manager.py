from .db_manager import DBManager
import os
from typing import List, override, Optional
from logging import Logger


class SqliteDBManager(DBManager):
    """
    This class is used to manage sqlite database connections.
    It extends the DBManager class and implements the required methods for managing sqlite database connections.
    """

    def __init__(self, instance_id: str, logger: Optional[Logger] = None) -> None:
        """
        Initializes the SqliteDBManager
        :param instance_id: The UUID of the instance (aka the Workflow run to be analyzed)
        :type instance_id: str
        :param logger: An instance of the Logger class for logging. If not provided, a default logger will be used.
        :type logger: Optional[Logger]
        :raises TypeError: If the logger is not an instance of Logger or None.
        """
        
        super().__init__(instance_id, logger)
        
        raise NotImplementedError("SQLiteDBManager is not yet implemented.")
        
        
    @override
    def get_findings(self) -> List[any]:
        """
        Retrieves **all** findings from the sqlite database which are associated to the class variable `instance_id`.
    
        :return: A list of findings retrieved from the sqlite database.
        """

        pass

        
    def __del__(self):
        """
        Cleans up the SqliteDBManager instance.
        """

        super().__del__()