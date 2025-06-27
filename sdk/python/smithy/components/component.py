from typing import Union, List, Optional
from logging import Logger
from abc import ABC
import uuid

from smithy.helpers.logger import log
from smithy.remote_store.findings_service.v1 import findings_service_pb2
from smithy.dbmanagers import RemoteDBManager, PostgresDBManager, SqliteDBManager
from smithy.enums.db_type_enum import DBTypeEnum


class Component(ABC):
    """
    A component in the Smithy Python SDK that represents a component in the smithy framework.
    """

    def __init__(
        self,
        instance_id: Union[uuid.UUID, str],
        db_type: DBTypeEnum,
        logger: Optional[Logger] = None,
    ) -> None:
        """
        Initializes a new instance of the Component class.
        **ATTENTION**: Currently only the `remote` database type is supported, all other types will raise a `NotImplementedError`.
        :param instance_id: The UUID of the instance (aka the Workflow run to be analyzed)
        :type instance_id: Union[uuid.UUID, str]
        :param db_type: The database mode for the enricher, DBTypeEnum, can be either `SQLITE`, `POSTGRES` or `REMOTE`. (remote is gRPC)
        :type db_type: DBTypeEnum
        :param logger: Optional an instance of the Logger class for logging, if not provided, a default logger will be used.
        :type logger: Optional[Logger]
        :raises ValueError: If the instance_id is not a valid UUID.
        :raises TypeError: If the instance_id is not a string or UUID object, or the logger is not an instance of Logger or None.
        """

        if not logger:
            self.log = log
        elif isinstance(logger, Logger):
            self.log = logger
        else:
            raise TypeError("logger must be an instance of Logger or None.")

        if instance_id is None or (
            not isinstance(instance_id, str) and not isinstance(instance_id, uuid.UUID)
        ):
            raise TypeError("instance_id must be a string or UUID object.")

        if isinstance(instance_id, uuid.UUID):
            instance_id = str(instance_id)

        self.instance_id = uuid.UUID(instance_id, version=4)

        if not db_type or not isinstance(db_type, DBTypeEnum):
            raise TypeError("db_type must be a DBTypeEnum.")

        match db_type:
            case DBTypeEnum.SQLITE:
                self.db_manager = SqliteDBManager()
            case DBTypeEnum.POSTGRES:
                self.db_manager = PostgresDBManager()
            case DBTypeEnum.REMOTE:
                self.db_manager = RemoteDBManager(
                    instance_id=str(self.instance_id), logger=self.log
                )
            case _:
                raise ValueError(
                    "db_type must be one of DBTypeEnum.SQLITE, DBTypeEnum.POSTGRES, or DBTypeEnum.REMOTE."
                )

    def get_findings(
        self, page_num: Optional[int] = None
    ) -> Union[List[findings_service_pb2.Finding], List[any]]:
        """
        This method helps you to retrieve findings from the database.
        It will use the database mode set in the component instance to determine how to retrieve the findings.

        :param page_num: Optional parameter to specify the page number for pagination. If not provided, all findings will be retrieved. Otherwise it will retrieve the `SMITHY_REMOTE_CLIENT_PAGE_SIZE`(default 100) findings for the given page number.
        :type page_num: Optional[int]

        :return: The findings retrieved from the database. This could be a list of `findings_service_pb2.Finding` objects if using the remote database mode, or a list of findings in the format defined by the specific database manager if using `SQLITE` or `POSTGRES`.
        """

        return self.db_manager.get_findings(page_num=page_num)

    def update_findings(self, findings: List[any]) -> bool:
        """
        This method helps you to update findings in the database.
        It will use the database mode set in the component instance to determine how to update the findings.

        :param findings: A list of findings to be updated in the database. The format of the findings should match the expected format of the specific database manager being used.
        :type findings: List[any]
        :return: True if the update was successful, False otherwise.
        :rtype: bool
        """

        return self.db_manager.update_findings(findings)

    def create_findings(self, findings: List[any]) -> bool:
        """
        This method helps you to create new findings in the database.
        It will use the database mode set in the component instance to determine how to create the findings.

        :param findings: A list of findings to be created in the database. The format of the findings should match the expected format of the specific database manager being used.
        :type findings: List[any]
        :return: True if the creation was successful, False otherwise.
        :rtype: bool
        """

        return self.db_manager.create_findings(findings)

    def __del__(self):
        """
        Destructor for the Component class.
        Closes the gRPC channel if it is open.
        """
        if hasattr(self, "db_manager") and self.db_manager:
            del self.db_manager
