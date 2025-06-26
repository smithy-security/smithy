from logging import Logger
from typing import List, Optional, override

from smithy.dbmanagers.db_manager import DBManager


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
    def get_findings(self, page_num: Optional[int] = None) -> List[any]:
        """
        Retrieves **all** findings from the sqlite database (unless `page_num` is used) which are associated to the class variable `instance_id`.

        :param page_num: Optional parameter to specify the page number for pagination. If not provided, all findings will be retrieved. Otherwise it will retrieve the `SMITHY_REMOTE_CLIENT_PAGE_SIZE`(default 100) findings for the given page number.
        :type page_num: Optional[int]

        :return: A list of findings retrieved from the sqlite database.
        """

        pass

    def __del__(self):
        """
        Cleans up the SqliteDBManager instance.
        """

        super().__del__()
