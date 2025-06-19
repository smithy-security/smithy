from .db_manager import DBManager
import grpc, os
from typing import List, override, Optional, Union
from logging import Logger
from smithy_python.remote_store.findings_service.v1.findings_service_pb2_grpc import FindingsServiceStub
from smithy_python.remote_store.findings_service.v1.findings_service_pb2 import GetFindingsRequest, Finding, UpdateFindingsRequest, CreateFindingsRequest
from smithy_python.ocsf.ocsf_schema.v1.ocsf_schema_pb2 import VulnerabilityFinding


class RemoteDBManager(DBManager):
    """
    This class is used to manage remote database connections.
    It extends the DBManager class and implements the required methods for managing remote database connections.
    """

    def __init__(self, instance_id: str, logger: Optional[Logger] = None) -> None:
        """
        Initializes the RemoteDBManager
        :param instance_id: The UUID of the instance (aka the Workflow run to be analyzed)
        :type instance_id: str
        :param logger: An instance of the Logger class for logging. If not provided, a default logger will be used.
        :type logger: Optional[Logger]
        :raises TypeError: If the logger is not an instance of Logger or None.
        """
        
        super().__init__(instance_id, logger)
    
        self._load_environment_variables()

        self._channel = grpc.insecure_channel(
            self.remote_store_findings_adress
        )

        self.stub = FindingsServiceStub(self._channel)
        
    @override
    def get_findings(self) -> List[Finding]:
        """
        Retrieves **all** findings from the remote database which are associated to the class variable `instance_id`.
        
        :return: A list of findings retrieved from the remote database.
        """
        
        page = 1
        all_findings = []
        try:
            while True:
                resp = self.stub.GetFindings(GetFindingsRequest(id=self.instance_id, page=page, page_size=self.remote_client_page_size))
                all_findings.extend(resp.findings)
                if len(resp.findings) < self.remote_client_page_size:
                    break
                page += 1
        except grpc.RpcError as e:
            self.log.error(f"Failed to retrieve findings from remote database: {e}")

        return all_findings
    
    @override
    def update_findings(self, findings: List[Finding]) -> bool:
        """
        Update the given findings in the remote database.
        
        :param findings: A list of findings to update in the remote database.
        :type findings: List[Finding]
        :return: True if the update was successful, False otherwise.
        :rtype: bool
        """

        if not self._validate_findings_list(findings):
            return False
        
        try:
            for i in range(0, len(findings), self.remote_client_page_size):
                batch = findings[i:i+self.remote_client_page_size]
                self.stub.UpdateFindings(UpdateFindingsRequest(id=self.instance_id, findings=batch))
        except grpc.RpcError as e:
            self.log.error(f"Failed to update findings in remote database: {e}")
            return False
        
        return True

    @override
    def create_findings(self, findings: List[VulnerabilityFinding]) -> bool:
        """
        Create the new findings in the remote database.

        :param findings: A list of VulnerabilityFindings to create in the remote database. (Note: This needs to be a list of VulnerabilityFinding objects, not Finding objects, because we creat the associated unique IDs for each finding in the remote database.)
        :type findings: List[VulnerabilityFinding]
        :return: True if the creation was successful, False otherwise.
        """

        if not self._validate_findings_list(findings):
            return False
        
        try:
            for i in range(0, len(findings), self.remote_client_page_size):
                batch = findings[i:i+self.remote_client_page_size]
                self.stub.CreateFindings(CreateFindingsRequest(id=self.instance_id, findings=batch))

        except grpc.RpcError as e:
            self.log.error(f"Failed to create findings in remote database: {e}")
            return False
        
        return True
    
        
    def __del__(self):
        """
        Cleans up the RemoteDBManager instance.
        Closes the gRPC channel when the instance is deleted.
        """
        
        if hasattr(self, '_channel') and self._channel:
            self._channel.close()

        
    def _validate_findings_list(self, findings: Union[List[Finding], List[VulnerabilityFinding]]) -> bool:
        """
        Validates the findings list to ensure it contains only Finding objects.
        
        :param findings: The list of findings to validate.
        :type findings: List[Finding]
        :return: True if the list is valid, False otherwise.
        """

        if not isinstance(findings, list) or not all(isinstance(finding, (Finding, VulnerabilityFinding)) for finding in findings):
            self.log.error("Invalid or findings provided for update. Must be a list of Finding objects.")
            return False
        
        if not findings:
            self.log.warning("No findings provided for update. Skipping update.")
            return False
        
        self.log.info(f"Valid findings list provided!")
        return True
    
    def _load_environment_variables(self):
        """
        Loads all the environment variables required for the remote database connection.
        """

        self.remote_store_findings_adress = os.getenv("SMITHY_REMOTE_STORE_FINDINGS_SERVICE_ADDR", "localhost:50051")
        self.remote_client_max_attempts = int(os.getenv("SMITHY_REMOTE_CLIENT_MAX_ATTEMPTS", 10))
        self.remote_client_initial_backoff_seconds = os.getenv("SMITHY_REMOTE_CLIENT_INITIAL_BACKOFF_SECONDS", "5s")
        self.remote_client_max_backoff_seconds = os.getenv("SMITHY_REMOTE_CLIENT_MAX_BACKOFF_SECONDS", "60s")
        self.remote_client_backoff_multiplier = float(os.getenv("SMITHY_REMOTE_CLIENT_BACKOFF_MULTIPLIER", 1.5))
        self.remote_client_page_size = int(os.getenv("SMITHY_REMOTE_CLIENT_PAGE_SIZE", 100))
