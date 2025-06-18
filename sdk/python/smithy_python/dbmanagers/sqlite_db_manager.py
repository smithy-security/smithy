from .db_manager import DBManager
import os
from typing import List, override


class SqliteDBManager(DBManager):
    """
    This class is used to manage sqlite database connections.
    It extends the DBManager class and implements the required methods for managing sqlite database connections.
    """

    def __init__(self):
        """
        Initializes the SqliteDBManager
        """
        
        super().__init__()
        
        raise NotImplementedError("SQLiteDBManager is not yet implemented.")
        
        
    @override
    def get_findings(self, query: str) -> List[any]:
        """
        Retrieves findings from the sqlite database using the provided query.
        
        :param query: The query to retrieve findings.
        :type query: str
        :return: A list of findings retrieved from the sqlite database.
        """

        pass

        
    def __del__(self):
        """
        Cleans up the SqliteDBManager instance.
        """

        super().__del__()