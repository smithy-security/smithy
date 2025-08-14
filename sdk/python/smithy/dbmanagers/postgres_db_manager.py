from typing import List, override, Optional
from logging import Logger

from smithy.dbmanagers.db_manager import DBManager
from findings_service.v1 import findings_service_pb2


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
    def get_findings(
        self, page_num: Optional[int] = None, page_size: Optional[int] = None
    ) -> List[findings_service_pb2.Finding]:
        """
        Retrieves **all** findings from the postgres database (unless `page_num` is used) which are associated to the class variable `instance_id`.

        :param page_num: Optional parameter to specify the page number for pagination. If not provided, all findings will be retrieved. Otherwise it will retrieve the `SMITHY_REMOTE_CLIENT_PAGE_SIZE`(default 100) findings for the given page number.
        :type page_num: Optional[int]


        :return: A list of findings retrieved from the postgres database.
        """

        pass

    def __del__(self):
        """
        Cleans up the PostgresDBManager instance.
        """

        super().__del__()
