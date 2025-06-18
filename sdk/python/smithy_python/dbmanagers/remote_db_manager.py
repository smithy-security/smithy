from .db_manager import DBManager
import os, grpc
from typing import List, override
from smithy_python.remote_store.findings_service.v1.findings_service_pb2_grpc import FindingsServiceStub
from smithy_python.remote_store.findings_service.v1.findings_service_pb2 import GetFindingsRequest, Finding


class RemoteDBManager(DBManager):
    """
    This class is used to manage remote database connections.
    It extends the DBManager class and implements the required methods for managing remote database connections.
    """

    def __init__(self, instance_id: str):
        """
        Initializes the RemoteDBManager
        :param instance_id: The UUID of the component instance.
        :type instance_id: str
        """
        
        super().__init__()
        
        self.instance_id = instance_id

        self.remote_store_findings_adress = os.getenv("SMITHY_REMOTE_STORE_FINDINGS_SERVICE_ADDR")
        if not self.remote_store_findings_adress:
            self.log.warning("SMITHY_REMOTE_STORE_FINDINGS_SERVICE_ADDR environment variable is not set, using default value 'localhost:50051'.")
            self.remote_store_findings_adress = "localhost:50051"

        self.remote_client_max_attempts = os.getenv("SMITHY_REMOTE_CLIENT_MAX_ATTEMPTS")
        if not self.remote_client_max_attempts:
            self.log.warning("SMITHY_REMOTE_CLIENT_MAX_ATTEMPTS environment variable is not set, using default value '10'.")
            self.remote_client_max_attempts = 10

        self.remote_client_initial_backoff_seconds = os.getenv("SMITHY_REMOTE_CLIENT_INITIAL_BACKOFF_SECONDS")
        if not self.remote_client_initial_backoff_seconds:
            self.log.warning("SMITHY_REMOTE_CLIENT_INITIAL_BACKOFF_SECONDS environment variable is not set, using default value '5s'.")
            self.remote_client_initial_backoff_seconds = "5s"

        self.remote_client_max_backoff_seconds = os.getenv("SMITHY_REMOTE_CLIENT_MAX_BACKOFF_SECONDS")
        if not self.remote_client_max_backoff_seconds:
            self.log.warning("SMITHY_REMOTE_CLIENT_MAX_BACKOFF_SECONDS environment variable is not set, using default value '60s'.")
            self.remote_client_max_backoff_seconds = "60s"

        self.remote_client_backoff_multiplier = os.getenv("SMITHY_REMOTE_CLIENT_BACKOFF_MULTIPLIER")
        if not self.remote_client_backoff_multiplier:
            self.log.warning("SMITHY_REMOTE_CLIENT_BACKOFF_MULTIPLIER environment variable is not set, using default value '1.5'.")
            self.remote_client_backoff_multiplier = 1.5

        self._channel = grpc.insecure_channel(
            self.remote_store_findings_adress
        )

        self.stub = FindingsServiceStub(self._channel)
        
    @override
    def get_findings(self) -> List[Finding]:
        """
        Retrieves findings from the remote database using the provided query.
        
        :return: A list of findings retrieved from the remote database.
        """

        request = GetFindingsRequest(id=self.instance_id)
        response = self.stub.GetFindings(request)

        return response.findings

        
    def __del__(self):
        """
        Cleans up the RemoteDBManager instance.
        Closes the gRPC channel when the instance is deleted.
        """
        if hasattr(self, '_channel') and self._channel:
            self._channel.close()
        