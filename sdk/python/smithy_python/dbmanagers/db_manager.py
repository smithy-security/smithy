from typing import List, Optional
from smithy_python.helpers.logger import log
from abc import ABC, abstractmethod
from logging import Logger

class DBManager(ABC):
    """
    Base class for database managers.
    This class should be extended by specific database managers to implement
    the required methods for managing database connections and operations.
    Therefore we are only defining the interface here, without any implementation details.
    """

    def __init__(self, instance_id:str, logger:Optional[Logger] = None) -> None:
        """
        Initializes the DBManager
        :param instance_id: The UUID of the instance (aka the Workflow run to be analyzed)
        :type instance_id: str
        :param logger: Optional an instance of the Logger class for logging, if not provided, a default logger will be used.
        :type logger: Optional[Logger]
        :raises TypeError: If the logger is not an instance of Logger or None.
        """
        
        self.instance_id = instance_id

        if not logger:
            self.log = log

        elif isinstance(logger, Logger):
            self.log = logger

        else:
            raise TypeError("logger must be an instance of Logger or None.")


    @abstractmethod
    def get_findings(self) -> List[any]:
        """
        Retrieves **all** findings from the postgres database which are associated to the class variable `instance_id`.
        
        :return: A list of findings retrieved from the database
        """

        raise NotImplementedError("This method should be implemented by subclasses.")
    
    @abstractmethod
    def update_findings(self, findings: List[any]) -> bool:
        """
        Updates the findings in the database.
        
        :param findings: A list of findings to be updated in the database.
        :type findings: List[any]
        :return: True if the update was successful, False otherwise.
        :rtype: bool
        """
        
        raise NotImplementedError("This method should be implemented by subclasses.")
    
    @abstractmethod
    def create_findings(self, findings: List[any]) -> bool:
        """
        Creates new findings in the database.
        
        :param findings: A list of findings to be created in the database.
        :type findings: List[any]
        :return: True if the creation was successful, False otherwise.
        :rtype: bool
        """
        
        raise NotImplementedError("This method should be implemented by subclasses.")