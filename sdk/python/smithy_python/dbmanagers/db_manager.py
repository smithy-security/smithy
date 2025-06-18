from typing import List
from smithy_python.helpers.logger import log 

class DBManager:
    """
    Base class for database managers.
    This class should be extended by specific database managers to implement
    the required methods for managing database connections and operations.
    Therefore we are only defining the interface here, without any implementation details.
    """

    def __init__(self):
        """
        Initializes the DBManager
        """
        self.log = log


    def get_findings(self) -> List[any]:
        """
        Retrieves findings from the database using the provided query.
        
        :param query: The query to retrieve findings.
        :type query: str
        :return: A list of findings retrieved from the database.
        """
        raise NotImplementedError("This method should be implemented by subclasses.")