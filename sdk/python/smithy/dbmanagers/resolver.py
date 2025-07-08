from logging import Logger
import os

from smithy.dbmanagers.remote_db_manager import RemoteDBManager
from smithy.dbmanagers.postgres_db_manager import PostgresDBManager
from smithy.dbmanagers.sqlite_db_manager import SqliteDBManager
from smithy.dbmanagers.db_manager import DBManager
from smithy.enums.db_type_enum import DBTypeEnum


class Resolver:
    """
    This class is responsible for resolving the appropriate database manager based on the provided parameters and will also load the necessary environment variables.
    """

    def __init__(self, logger: Logger) -> None:
        """
        Initializes the Resolver.

        :param logger: An instance of the Logger class for logging.
        :type logger: Logger
        """

        self._log = logger

    def resolve(self, instance_id: str, db_type) -> DBManager:
        """
        Resolves the appropriate database manager based on the provided parameters.

        :param instance_id: The UUID of the instance (aka the Workflow run to be analyzed).
        :type instance_id: str
        :param db_type: The type of database being used (REMOTE, SQLITE, POSTGRES).
        :type db_type: DBTypeEnum
        :return: An instance of the appropriate DBManager.
        :rtype: DBManager
        """

        if not isinstance(db_type, DBTypeEnum):
            raise TypeError("db_type must be an instance of DBTypeEnum.")

        match db_type:
            case DBTypeEnum.REMOTE:
                return RemoteDBManager(
                    instance_id=str(instance_id),
                    logger=self._log,
                )
            case DBTypeEnum.SQLITE:
                return SqliteDBManager(instance_id, self._log)
            case DBTypeEnum.POSTGRES:
                return PostgresDBManager(instance_id, self._log)
            case _:
                raise ValueError(f"Unsupported database type: {db_type}")
