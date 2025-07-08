from logging import Logger
from typing import List, Optional, override

from smithy.dbmanagers.db_manager import DBManager
from smithy.remote_store.findings_service.v1 import findings_service_pb2


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
    def get_findings(
        self, page_num: Optional[int] = None, page_size: Optional[int] = None
    ) -> List[findings_service_pb2.Finding]:
        """
        Retrieves **all** findings from the sqlite database (unless `page_num` is used) which are associated to the class variable `instance_id`.

        :param page_num: Optional parameter to specify the page number for pagination. If not provided, all findings will be retrieved. Otherwise it will retrieve the `SMITHY_REMOTE_CLIENT_PAGE_SIZE`(default 100) findings for the given page number.
        :type page_num: Optional[int]

        :param page_size: Optional parameter to specify the number of findings per page. If not provided, the page size specified by the ENV variable `SMITHY_REMOTE_CLIENT_PAGE_SIZE` will be used (default is 100).
        :type page_size: Optional[int]

        :return: A list of findings retrieved from the sqlite database.
        """

        pass

    def __del__(self):
        """
        Cleans up the SqliteDBManager instance.
        """

        super().__del__()
