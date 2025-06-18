import uuid, os, grpc
from typing import Union, List
from logging import Logger
from smithy_python.remote_store.findings_service.v1 import findings_service_pb2_grpc, findings_service_pb2
from smithy_python.dbmanagers import RemoteDBManager, PostgresDBManager, SqliteDBManager

class Component:
    """
    A component in the Smithy Python SDK that represents a component in the smithy framework.
    """

    def __init__(self, instance_id: Union[uuid.UUID, str], db_mode: str, logger: Logger):
        """
        Initializes a new instance of the Component class.
        **ATTENTION**: Currently only the `remote` database mode is supported, all other modes will raise a `NotImplementedError`.
        :param instance_id: The UUID of the component instance.
        :type instance_id: Union[uuid.UUID, str]
        :param db_mode: The database mode for the component, either `sqlite`, `postgres` or `remote`. (remote is gRPC)
        :type db_mode: str
        :param logger: An instance of the Logger class for logging.
        :type logger: Logger
        :raises ValueError: If the instance_id is not a valid UUID.
        :raises TypeError: If the instance_id is not a string or UUID object.
        """
        
        self.log = logger

        if instance_id is None or (not isinstance(instance_id, str) and not isinstance(instance_id, uuid.UUID)):
            raise TypeError("instance_id must be a string or UUID object.")
        
        if isinstance(instance_id, uuid.UUID):
            instance_id = str(instance_id)

        if not self._validate_uuid(instance_id):
            raise ValueError(f"Invalid UUID: {instance_id}")
        
        self.instance_id = instance_id

        if not db_mode or not isinstance(db_mode, str):
            raise TypeError("db_mode must be a string.")
        
        
        match db_mode:
            case "sqlite":
                self.db_manager = SqliteDBManager()
            case "postgres":
                self.db_manager = PostgresDBManager()
            case "remote":
                self.db_manager = RemoteDBManager(instance_id=self.instance_id)
            case _:
                raise ValueError("db_mode must be one of 'sqlite', 'postgres', or 'remote'.")


    def get_findings(self) -> Union[List[findings_service_pb2.Finding]]:
        """
        This method helps you to retrieve findings from the database.
        It will use the database mode set in the component instance to determine how to retrieve the findings.
        
        :return: The findings retrieved from the database.
        """
        

        return self.db_manager.get_findings()


    def __del__(self):
        """
        Destructor for the Component class.
        Closes the gRPC channel if it is open.
        """
        if hasattr(self, 'db_manager') and self.db_manager:
            del self.db_manager
        

    def _validate_uuid(self, instance_id: str) -> bool:
        """
        Validates the UUID of the component instance.

        :param instance_id: The string representing a UUID to validate.
        :return: True if the UUID is valid, False otherwise.
        """

        try:
            val = uuid.UUID(instance_id, version=4)
        except ValueError:
            return False
        return str(val) == instance_id.lower()