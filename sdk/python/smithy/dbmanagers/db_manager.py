from abc import ABC, abstractmethod
from logging import Logger
from typing import List, Optional

from smithy.helpers.logger import log
from findings_service.v1 import findings_service_pb2


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
            self._log = log

        elif isinstance(logger, Logger):
            self._log = logger

        else:
            raise TypeError("logger must be an instance of Logger or None.")

    @abstractmethod
    def get_findings(
        self, page_num: Optional[int] = None, page_size: Optional[int] = None
    ) -> List[findings_service_pb2.Finding]:
        """
        Retrieves **all** findings from the database unless `page_num` is used) which are associated to the class variable `instance_id`.

        :param page_num: Optional parameter to specify the page number for pagination. If not provided, all findings will be retrieved. Otherwise it will retrieve the `SMITHY_REMOTE_CLIENT_PAGE_SIZE`(default 100) findings for the given page number.
        :type page_num: Optional[int]

        :param page_size: Optional parameter to specify the number of findings per page. If not provided, the page size specified by the ENV variable `SMITHY_REMOTE_CLIENT_PAGE_SIZE` will be used (default is 100).
        :type page_size: Optional[int]

        :return: A list of findings retrieved from the database
        :rtype: List[findings_service_pb2.Finding]
        """

        raise NotImplementedError("This method should be implemented by subclasses.")

    @abstractmethod
    def update_findings(self, findings: List[findings_service_pb2.Finding]) -> bool:
        """
        Updates the findings in the database.

        :param findings: A list of findings to be updated in the database.
        :type findings: List[findings_service_pb2.Finding]
        :return: True if the update was successful, False otherwise.
        :rtype: bool
        """

        raise NotImplementedError("This method should be implemented by subclasses.")

    @abstractmethod
    def create_findings(self, findings: List[findings_service_pb2.Finding]) -> bool:
        """
        Creates new findings in the database.

        :param findings: A list of findings to be created in the database.
        :type findings: List[findings_service_pb2.Finding]
        :return: True if the creation was successful, False otherwise.
        :rtype: bool
        """

        raise NotImplementedError("This method should be implemented by subclasses.")

    @abstractmethod
    def close(self) -> None:
        """
        Closes the database connection.

        This method should be called when the database manager is no longer needed to release resources.
        """

        raise NotImplementedError("This method should be implemented by subclasses.")
