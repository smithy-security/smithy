from abc import ABC, abstractmethod
from logging import Logger
from typing import List, Optional

from smithy.helpers.logger import log


class DBManager(ABC):
    """
    Base class for database managers.
    This class should be extended by specific database managers to implement
    the required methods for managing database connections and operations.
    Therefore we are only defining the interface here, without any implementation details.
    """

    def __init__(self, instance_id: str, logger: Optional[Logger] = None) -> None:
        """
        Initializes the DBManager
        :param instance_id: The UUID of the instance (aka the Workflow run to be analyzed)
        :type instance_id: str
        :param logger: Optional an instance of the Logger class for logging, if not provided, a default logger will be used.
        :type logger: Optional[Logger]
        :raises TypeError: If the logger is not an instance of Logger or None.
        """

        # Initialize variables with sensible defaults that get also used by other classes which import subclasses of this class. We want to make sure that those DB related variables are always set.
        self.page_size = 100  # Default page size for pagination

        self.instance_id = instance_id

        if not logger:
            self.log = log

        elif isinstance(logger, Logger):
            self.log = logger

        else:
            raise TypeError("logger must be an instance of Logger or None.")

    @abstractmethod
    def get_findings(self, page_num: Optional[int] = None) -> List[any]:
        """
        Retrieves **all** findings from the database unless `page_num` is used) which are associated to the class variable `instance_id`.

        :param page_num: Optional parameter to specify the page number for pagination. If not provided, all findings will be retrieved. Otherwise it will retrieve the `SMITHY_REMOTE_CLIENT_PAGE_SIZE`(default 100) findings for the given page number.
        :type page_num: Optional[int]
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
